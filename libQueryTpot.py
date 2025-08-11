"""
T-Pot Elasticsearch Query Library

A robust library for querying T-Pot honeypot Elasticsearch data with proper
error handling, retry logic, and memory-aware processing.

Author: [Your Name]
Version: 2.0.0
"""

import logging
import time
import json
import os
from datetime import datetime, timedelta
from typing import List, Dict, Optional, Any, Union, Tuple
from collections import Counter
from contextlib import contextmanager

from elasticsearch import Elasticsearch, exceptions as es_exceptions
from tqdm import tqdm


class CircuitBreakerError(Exception):
    """Raised when Elasticsearch circuit breaker is triggered"""
    pass


class TPotQuery:
    """
    Query T-Pot Elasticsearch data with robust error handling and retry logic.

    This class provides methods to:
    - Pull recent logs with type filtering
    - Export data with automatic file splitting
    - Handle circuit breaker errors gracefully
    - Automatically retry on transient failures
    - Clean up resources properly
    """

    # Class constants
    DEFAULT_BATCH_SIZE = 500  # Reduced from 1000 to avoid circuit breaker
    DEFAULT_SCROLL_TIME = '2m'
    MAX_RETRIES = 3
    RETRY_DELAY = 2  # seconds
    CIRCUIT_BREAKER_DELAY = 10  # seconds

    def __init__(
            self,
            es_host: str,
            index_name: str,
            api_key_id: str,
            api_key: str,
            batch_size: int = DEFAULT_BATCH_SIZE,
            scroll_time: str = DEFAULT_SCROLL_TIME,
            config: Optional[Dict[str, Any]] = None
    ):
        """
        Initialize TPotQuery with Elasticsearch connection.

        Args:
            es_host: Elasticsearch server URL (e.g., 'https://10.0.0.27:9200')
            index_name: Index pattern to query (e.g., 'logstash-*')
            api_key_id: Elasticsearch API key ID
            api_key: Elasticsearch API key value
            batch_size: Documents per batch (default: 500)
            scroll_time: Scroll context retention (default: '2m')
            config: Full configuration dictionary from config.yml

        Raises:
            ValueError: If required parameters are missing
            ConnectionError: If unable to connect to Elasticsearch
        """
        # Validate required parameters
        if not all([es_host, index_name, api_key_id, api_key]):
            raise ValueError("Missing required Elasticsearch connection parameters")

        self.es_host = es_host
        self.index_name = index_name
        self.batch_size = min(batch_size, 500)  # Cap at 500 to avoid memory issues
        self.scroll_time = scroll_time
        self.config = config or {}
        self.request_timeout = 30  # Default timeout for ES requests

        # Extract ignore_types from config with fallback
        self.ignore_types = []
        if config and 'tpot' in config and 'ignore_types' in config['tpot']:
            self.ignore_types = config['tpot']['ignore_types']
            logging.info(f"Configured to ignore types: {self.ignore_types}")

        # Initialize results storage
        self.results = []

        # Setup Elasticsearch connection with retry
        self._connect_with_retry(api_key_id, api_key)

        # Verify connection
        self._verify_connection()

    def _connect_with_retry(self, api_key_id: str, api_key: str) -> None:
        """
        Establish Elasticsearch connection with retry logic.

        Args:
            api_key_id: API key ID
            api_key: API key value

        Raises:
            ConnectionError: If unable to connect after retries
        """
        for attempt in range(self.MAX_RETRIES):
            try:
                # For Elasticsearch 9.x, timeout is set via request_timeout parameter
                # in individual operations, not in the constructor
                self.es = Elasticsearch(
                    hosts=[self.es_host],
                    api_key=(api_key_id, api_key),
                    verify_certs=False
                )
                return
            except es_exceptions.ConnectionError as e:
                if attempt < self.MAX_RETRIES - 1:
                    logging.warning(f"Connection attempt {attempt + 1} failed, retrying...")
                    time.sleep(self.RETRY_DELAY * (2 ** attempt))  # Exponential backoff
                else:
                    logging.error(f"Failed to connect to Elasticsearch after {self.MAX_RETRIES} attempts")
                    raise ConnectionError(f"Unable to connect to Elasticsearch: {e}")

    def _verify_connection(self) -> None:
        """
        Verify Elasticsearch connection is working.

        Raises:
            ConnectionError: If cluster is not reachable
        """
        try:
            info = self.es.info()
            logging.info(f"Connected to Elasticsearch cluster: {info['cluster_name']}")
        except Exception as e:
            raise ConnectionError(f"Failed to verify Elasticsearch connection: {e}")

    @contextmanager
    def _scroll_context(self, initial_response: Dict[str, Any]):
        """
        Context manager to ensure scroll contexts are always cleaned up.

        Args:
            initial_response: Initial search response with scroll_id

        Yields:
            scroll_id: The scroll ID for subsequent requests
        """
        scroll_id = initial_response.get('_scroll_id')
        try:
            yield scroll_id
        finally:
            # Always clean up scroll context
            if scroll_id:
                try:
                    self.es.clear_scroll(scroll_id=scroll_id)
                    logging.debug("Scroll context cleaned up")
                except Exception as e:
                    logging.warning(f"Failed to clear scroll context: {e}")

    def _execute_with_retry(
            self,
            func,
            *args,
            handle_circuit_breaker: bool = True,
            **kwargs
    ) -> Any:
        """
        Execute Elasticsearch operation with retry logic.

        Args:
            func: Function to execute
            *args: Positional arguments for func
            handle_circuit_breaker: Whether to handle circuit breaker errors
            **kwargs: Keyword arguments for func

        Returns:
            Result from func

        Raises:
            Exception: If all retries fail
        """
        last_exception = None

        for attempt in range(self.MAX_RETRIES):
            try:
                return func(*args, **kwargs)

            except es_exceptions.ApiError as e:
                # Check for circuit breaker error (429)
                if e.status_code == 429 and handle_circuit_breaker:
                    logging.warning(f"Circuit breaker triggered, waiting {self.CIRCUIT_BREAKER_DELAY}s...")
                    time.sleep(self.CIRCUIT_BREAKER_DELAY)

                    # Reduce batch size for next attempt
                    if 'size' in kwargs:
                        kwargs['size'] = max(100, kwargs['size'] // 2)
                        logging.info(f"Reduced batch size to {kwargs['size']}")

                    last_exception = CircuitBreakerError(str(e))
                else:
                    last_exception = e

            except (es_exceptions.ConnectionTimeout, es_exceptions.ConnectionError) as e:
                logging.warning(f"Connection error on attempt {attempt + 1}: {e}")
                last_exception = e

            except Exception as e:
                logging.error(f"Unexpected error: {e}")
                last_exception = e

            # Retry with exponential backoff
            if attempt < self.MAX_RETRIES - 1:
                delay = self.RETRY_DELAY * (2 ** attempt)
                logging.info(f"Retrying in {delay} seconds...")
                time.sleep(delay)

        # All retries failed
        raise last_exception or Exception("Operation failed after all retries")

    def pull_recent_logs(self, minutes_back: int = 5) -> List[Dict[str, Any]]:
        """
        Pull logs from Elasticsearch within the specified time window.

        Filters out types specified in ignore_types configuration.

        Args:
            minutes_back: Number of minutes to look back (default: 5)

        Returns:
            List of matching documents from Elasticsearch

        Note:
            Results are stored in self.results for backward compatibility
        """
        # Calculate time range
        time_to = datetime.now()
        time_from = time_to - timedelta(minutes=minutes_back)

        # Build query with ignore_types filter
        query_body = self._build_filtered_query(
            time_from=time_from,
            time_to=time_to,
            exclude_types=self.ignore_types
        )

        logging.info(f"Pulling logs from {time_from} to {time_to}")
        if self.ignore_types:
            logging.info(f"Excluding types: {self.ignore_types}")

        all_results = []
        batch_count = 0

        try:
            # Initial search with retry
            response = self._execute_with_retry(
                self.es.search,
                index=self.index_name,
                body=query_body,
                scroll=self.scroll_time,
                size=self.batch_size,
                request_timeout=self.request_timeout
            )

            total_hits = response['hits']['total']['value']
            logging.info(f"Found {total_hits} matching documents")

            with self._scroll_context(response) as scroll_id:
                # Process initial batch
                hits = response['hits']['hits']

                # Use progress bar if we have many documents
                use_progress = total_hits > 1000
                pbar = tqdm(total=total_hits, desc="Fetching logs") if use_progress else None

                try:
                    while hits:
                        # Extract source documents
                        for hit in hits:
                            all_results.append(hit['_source'])

                        batch_count += 1
                        if pbar:
                            pbar.update(len(hits))

                        # Log progress every 10 batches
                        if batch_count % 10 == 0:
                            logging.debug(f"Processed {len(all_results)} documents...")

                        # Get next batch with retry and circuit breaker handling
                        try:
                            response = self._execute_with_retry(
                                self.es.scroll,
                                scroll_id=scroll_id,
                                scroll=self.scroll_time,
                                request_timeout=self.request_timeout,
                                handle_circuit_breaker=True
                            )
                            hits = response['hits']['hits']
                        except CircuitBreakerError:
                            logging.warning("Circuit breaker persists, stopping fetch")
                            break

                finally:
                    if pbar:
                        pbar.close()

            logging.info(f"Successfully fetched {len(all_results)} documents in {batch_count} batches")

        except Exception as e:
            logging.error(f"Failed to retrieve logs: {e}", exc_info=True)
            # Return what we got so far
            if all_results:
                logging.info(f"Returning partial results: {len(all_results)} documents")

        # Store in instance variable for backward compatibility
        self.results = all_results
        return all_results

    def _build_filtered_query(
            self,
            time_from: Optional[datetime] = None,
            time_to: Optional[datetime] = None,
            exclude_types: Optional[List[str]] = None,
            include_types: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """
        Build Elasticsearch query with filters.

        Args:
            time_from: Start time for range query
            time_to: End time for range query
            exclude_types: Types to exclude
            include_types: Types to include (whitelist)

        Returns:
            Query body dictionary
        """
        must_clauses = []
        must_not_clauses = []

        # Time range filter
        if time_from or time_to:
            range_clause = {"range": {"@timestamp": {}}}
            if time_from:
                range_clause["range"]["@timestamp"]["gte"] = time_from.isoformat()
            if time_to:
                range_clause["range"]["@timestamp"]["lte"] = time_to.isoformat()
            must_clauses.append(range_clause)

        # Type filters
        if include_types:
            # Whitelist mode
            must_clauses.append({
                "terms": {"type": include_types}
            })
        elif exclude_types:
            # Blacklist mode
            must_not_clauses.append({
                "terms": {"type": exclude_types}
            })

        # Build final query
        if must_clauses or must_not_clauses:
            query = {"bool": {}}
            if must_clauses:
                query["bool"]["must"] = must_clauses
            if must_not_clauses:
                query["bool"]["must_not"] = must_not_clauses
        else:
            query = {"match_all": {}}

        return {"query": query}

    def show_results(self, max_items: int = 10) -> None:
        """
        Display sample of results for debugging.

        Args:
            max_items: Maximum number of items to display
        """
        if not self.results:
            print("No results to display")
            return

        print(f"\n=== Sample Results (showing up to {max_items} of {len(self.results)}) ===")
        for i, result in enumerate(self.results[:max_items], 1):
            print(f"\n--- Result {i} ---")
            # Show key fields
            for key in ['@timestamp', 'type', 'src_ip', 'dest_port', 'honeypot']:
                if key in result:
                    print(f"{key}: {result[key]}")
        print("=" * 50)

    def summarize_type_field(self, entries: Optional[List[Dict]] = None) -> Dict[str, int]:
        """
        Summarize the distribution of 'type' field values.

        Args:
            entries: List of log entries (uses self.results if None)

        Returns:
            Dictionary of type counts
        """
        entries = entries or self.results

        if not entries:
            logging.warning("No entries to summarize")
            return {}

        type_counter = Counter(entry.get('type', 'unknown') for entry in entries)

        print("\n=== Type Field Summary ===")
        for type_name, count in type_counter.most_common():
            print(f"{type_name}: {count}")
        print(f"Total unique types: {len(type_counter)}")

        return dict(type_counter)

    def summarize_credentials(self, entries: Optional[List[Dict]] = None) -> Dict[str, int]:
        """
        Summarize username/password combinations from logs.

        Args:
            entries: List of log entries (uses self.results if None)

        Returns:
            Dictionary of credential combination counts
        """
        entries = entries or self.results

        if not entries:
            logging.warning("No entries to summarize")
            return {}

        cred_counter = Counter()

        for entry in entries:
            username = entry.get('username', '')
            password = entry.get('password', '')

            if username or password:
                cred_combo = f"{username}:{password}"
                cred_counter[cred_combo] += 1

        if cred_counter:
            print("\n=== Top Credential Combinations ===")
            for combo, count in cred_counter.most_common(20):
                print(f"{combo}: {count}")
            print(f"Total unique combinations: {len(cred_counter)}")
        else:
            print("\n=== No credentials found in logs ===")

        return dict(cred_counter)

    def summarize_hashes(self, entries: Optional[List[Dict]] = None) -> Dict[str, int]:
        """
        Summarize file hashes from logs.

        Args:
            entries: List of log entries (uses self.results if None)

        Returns:
            Dictionary of hash counts
        """
        entries = entries or self.results

        if not entries:
            logging.warning("No entries to summarize")
            return {}

        hash_counter = Counter()
        hash_fields = ['md5', 'sha256', 'sha1', 'shasum', 'file_hash']

        for entry in entries:
            for field in hash_fields:
                if field in entry and entry[field]:
                    hash_value = entry[field]
                    if isinstance(hash_value, str) and len(hash_value) > 10:
                        hash_counter[f"{field}:{hash_value}"] += 1

        if hash_counter:
            print("\n=== File Hashes Summary ===")
            for hash_info, count in hash_counter.most_common(20):
                print(f"{hash_info}: {count}")
            print(f"Total unique hashes: {len(hash_counter)}")
        else:
            print("\n=== No file hashes found in logs ===")

        return dict(hash_counter)

    def summarize_inputs(self, entries: Optional[List[Dict]] = None) -> Dict[str, int]:
        """
        Summarize input/command data from logs.

        Args:
            entries: List of log entries (uses self.results if None)

        Returns:
            Dictionary of input counts
        """
        entries = entries or self.results

        if not entries:
            logging.warning("No entries to summarize")
            return {}

        input_counter = Counter()
        input_fields = ['input', 'command', 'payload', 'request', 'data']

        for entry in entries:
            for field in input_fields:
                if field in entry and entry[field]:
                    input_value = str(entry[field])[:200]  # Truncate long inputs
                    if len(input_value) > 3:  # Skip very short inputs
                        input_counter[input_value] += 1

        if input_counter:
            print("\n=== Top Inputs/Commands ===")
            for input_data, count in input_counter.most_common(20):
                # Sanitize for display
                safe_input = input_data.replace('\n', '\\n')[:100]
                print(f"{safe_input}: {count}")
            print(f"Total unique inputs: {len(input_counter)}")
        else:
            print("\n=== No input data found in logs ===")

        return dict(input_counter)

    def export_filtered_data(
            self,
            output_file: Optional[str] = None,
            minutes_back: Optional[int] = None,
            include_types: Optional[List[str]] = None,
            exclude_types: Optional[List[str]] = None,
            include_metadata: bool = False,
            max_file_size_mb: int = 50,
            max_records_per_file: Optional[int] = None
    ) -> List[str]:
        """
        Export filtered data with automatic file splitting.

        Args:
            output_file: Base filename (auto-generated if None)
            minutes_back: Time window in minutes
            include_types: Types to include (whitelist)
            exclude_types: Types to exclude (blacklist)
            include_metadata: Include ES metadata fields
            max_file_size_mb: Max file size before splitting
            max_records_per_file: Max records per file

        Returns:
            List of created output filenames
        """
        # Generate base filename
        if output_file is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            base_name = f"tpot_export_{timestamp}"
        else:
            base_name = os.path.splitext(output_file)[0]

        # Build query
        query_body = self._build_filtered_query(
            time_from=datetime.now() - timedelta(minutes=minutes_back) if minutes_back else None,
            exclude_types=exclude_types or self.ignore_types,
            include_types=include_types
        )

        logging.info(f"Starting filtered export from index '{self.index_name}'")

        try:
            # Get initial response
            response = self._execute_with_retry(
                self.es.search,
                index=self.index_name,
                body=query_body,
                scroll=self.scroll_time,
                size=self.batch_size,
                request_timeout=self.request_timeout
            )

            total_docs = response['hits']['total']['value']
            logging.info(f"Total documents to export: {total_docs}")

            if total_docs == 0:
                logging.info("No documents match the filter criteria")
                return []

            # Process and export
            output_files = self._process_export(
                response,
                base_name,
                include_metadata,
                max_file_size_mb,
                max_records_per_file
            )

            return output_files

        except Exception as e:
            logging.error(f"Export failed: {e}", exc_info=True)
            raise

    def _process_export(
            self,
            initial_response: Dict[str, Any],
            base_name: str,
            include_metadata: bool,
            max_file_size_mb: int,
            max_records_per_file: Optional[int]
    ) -> List[str]:
        """
        Process export with file splitting.

        Args:
            initial_response: Initial search response
            base_name: Base filename for output
            include_metadata: Whether to include metadata
            max_file_size_mb: Max file size in MB
            max_records_per_file: Max records per file

        Returns:
            List of created filenames
        """
        max_file_size_bytes = max_file_size_mb * 1024 * 1024
        output_files = []
        file_count = 1
        current_file_size = 0
        current_record_count = 0
        exported_count = 0

        # Initialize first file
        current_filename = f"{base_name}_part{file_count:03d}.jsonl"
        output_files.append(current_filename)
        current_file = open(current_filename, 'w', encoding='utf-8')

        total_docs = initial_response['hits']['total']['value']

        try:
            with self._scroll_context(initial_response) as scroll_id:
                hits = initial_response['hits']['hits']

                with tqdm(total=total_docs, desc="Exporting") as pbar:
                    while hits:
                        for hit in hits:
                            # Prepare document
                            if include_metadata:
                                doc = hit
                            else:
                                doc = hit['_source']

                            json_line = json.dumps(doc, ensure_ascii=False) + '\n'
                            line_size = len(json_line.encode('utf-8'))

                            # Check if we need a new file
                            need_new_file = False
                            if max_records_per_file and current_record_count >= max_records_per_file:
                                need_new_file = True
                            elif current_file_size + line_size > max_file_size_bytes:
                                need_new_file = True

                            if need_new_file and current_record_count > 0:
                                # Close current file and start new one
                                current_file.close()
                                file_count += 1
                                current_filename = f"{base_name}_part{file_count:03d}.jsonl"
                                output_files.append(current_filename)
                                current_file = open(current_filename, 'w', encoding='utf-8')
                                current_file_size = 0
                                current_record_count = 0
                                logging.info(f"Started new file: {current_filename}")

                            # Write document
                            current_file.write(json_line)
                            current_file_size += line_size
                            current_record_count += 1
                            exported_count += 1
                            pbar.update(1)

                        # Get next batch
                        try:
                            response = self._execute_with_retry(
                                self.es.scroll,
                                scroll_id=scroll_id,
                                scroll=self.scroll_time,
                                request_timeout=self.request_timeout
                            )
                            hits = response['hits']['hits']
                        except CircuitBreakerError:
                            logging.warning("Circuit breaker triggered during export, saving partial data")
                            break

        finally:
            # Always close the file
            if current_file and not current_file.closed:
                current_file.close()

        # Log summary
        logging.info(f"Export complete: {exported_count} documents in {len(output_files)} files")
        print(f"\nExport complete! {exported_count} documents saved to {len(output_files)} files:")
        for i, filename in enumerate(output_files, 1):
            if os.path.exists(filename):
                file_size = os.path.getsize(filename) / (1024 * 1024)
                print(f"  Part {i}: {filename} ({file_size:.2f} MB)")

        return output_files

    def export_all_data(
            self,
            output_file: Optional[str] = None,
            include_metadata: bool = False,
            max_file_size_mb: int = 50,
            max_records_per_file: Optional[int] = None
    ) -> List[str]:
        """
        Export all data from the index (no filters).

        Args:
            output_file: Base filename
            include_metadata: Include ES metadata
            max_file_size_mb: Max file size
            max_records_per_file: Max records per file

        Returns:
            List of created filenames
        """
        return self.export_filtered_data(
            output_file=output_file,
            minutes_back=None,
            include_types=None,
            exclude_types=[],  # Override ignore_types
            include_metadata=include_metadata,
            max_file_size_mb=max_file_size_mb,
            max_records_per_file=max_records_per_file
        )

    def export_by_time_periods(
            self,
            hours_per_file: int = 24,
            days_back: int = 7,
            output_dir: Optional[str] = None,
            include_metadata: bool = False
    ) -> List[str]:
        """
        Export data split by time periods.

        Args:
            hours_per_file: Hours of data per file
            days_back: Days to look back
            output_dir: Output directory
            include_metadata: Include ES metadata

        Returns:
            List of created filenames
        """
        if output_dir is None:
            output_dir = "."

        os.makedirs(output_dir, exist_ok=True)

        output_files = []
        end_time = datetime.now()
        start_time = end_time - timedelta(days=days_back)
        current_time = start_time

        logging.info(f"Exporting data from {start_time} to {end_time}")

        while current_time < end_time:
            period_end = min(current_time + timedelta(hours=hours_per_file), end_time)

            # Build time-specific query
            query_body = self._build_filtered_query(
                time_from=current_time,
                time_to=period_end,
                exclude_types=self.ignore_types
            )

            # Generate filename
            filename = f"tpot_{current_time.strftime('%Y%m%d_%H%M')}_to_{period_end.strftime('%Y%m%d_%H%M')}.jsonl"
            filepath = os.path.join(output_dir, filename)

            try:
                # Export this time period
                response = self._execute_with_retry(
                    self.es.search,
                    index=self.index_name,
                    body=query_body,
                    scroll=self.scroll_time,
                    size=self.batch_size,
                    request_timeout=self.request_timeout
                )

                if response['hits']['total']['value'] > 0:
                    self._export_time_period(
                        response,
                        filepath,
                        include_metadata
                    )
                    output_files.append(filepath)
                else:
                    logging.info(f"No data for period {current_time} to {period_end}")

            except Exception as e:
                logging.error(f"Failed to export period {current_time}: {e}")

            current_time = period_end

        return output_files

    def _export_time_period(
            self,
            initial_response: Dict[str, Any],
            filepath: str,
            include_metadata: bool
    ) -> None:
        """
        Export a single time period to file.

        Args:
            initial_response: Search response
            filepath: Output file path
            include_metadata: Include metadata
        """
        with open(filepath, 'w', encoding='utf-8') as f:
            with self._scroll_context(initial_response) as scroll_id:
                hits = initial_response['hits']['hits']
                count = 0

                while hits:
                    for hit in hits:
                        if include_metadata:
                            doc = hit
                        else:
                            doc = hit['_source']

                        f.write(json.dumps(doc, ensure_ascii=False) + '\n')
                        count += 1

                    # Get next batch
                    try:
                        response = self._execute_with_retry(
                            self.es.scroll,
                            scroll_id=scroll_id,
                            scroll=self.scroll_time,
                            request_timeout=self.request_timeout
                        )
                        hits = response['hits']['hits']
                    except CircuitBreakerError:
                        logging.warning("Circuit breaker triggered, saving partial period")
                        break

                logging.info(f"Exported {count} documents to {filepath}")

    def __del__(self):
        """Cleanup on deletion."""
        if hasattr(self, 'es'):
            try:
                self.es.close()
            except:
                pass
