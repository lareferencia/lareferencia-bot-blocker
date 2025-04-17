#!/usr/bin/env python3
"""
Test script to verify the reverse reading functionality.
"""
import os
import sys
import logging
from datetime import datetime, timedelta

from log_parser import process_log_in_chunks

# Configure basic logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger('test_reverse')

def simple_handler(lines, start_date=None):
    """Simple handler that checks dates and reports stats."""
    processed = 0
    dates = []
    outside_window = 0
    
    for line in lines:
        if '[' not in line:
            continue
            
        # Extract date for simple testing
        try:
            date_part = line.split('[')[1].split(']')[0].split()[0]
            dt = datetime.strptime(date_part, '%d/%b/%Y:%H:%M:%S')
            
            if start_date and dt < start_date:
                outside_window += 1
                continue
                
            dates.append(dt)
            processed += 1
            
        except (IndexError, ValueError):
            continue
    
    # Report on this chunk
    if dates:
        logger.info(f"Processed {processed} lines, {outside_window} outside window")
        logger.info(f"Date range: {min(dates)} to {max(dates)}")
    else:
        logger.info(f"No valid dates in this chunk. {outside_window} outside window")
    
    # Stop if all entries were outside the window
    if outside_window > 0 and processed == 0:
        logger.info("All entries in chunk were outside time window. Stopping.")
        return False
        
    return processed

def main():
    if len(sys.argv) < 2:
        print("Usage: python test_reverse_reading.py /path/to/logfile [lines]")
        return
    
    log_file = sys.argv[1]
    lines_to_read = int(sys.argv[2]) if len(sys.argv) > 2 else None
    
    if not os.path.exists(log_file):
        print(f"Error: File not found: {log_file}")
        return
    
    # Test normal reading
    logger.info("=== Testing normal reading ===")
    start_date = datetime.now() - timedelta(days=1)  # Last day
    logger.info(f"Using start date: {start_date}")
    
    process_log_in_chunks(
        log_file, 
        simple_handler, 
        chunk_size=1000,
        reverse=False, 
        start_date=start_date
    )
    
    # Test reverse reading
    logger.info("\n=== Testing reverse reading ===")
    process_log_in_chunks(
        log_file, 
        simple_handler, 
        chunk_size=1000,
        reverse=True, 
        start_date=start_date
    )

if __name__ == "__main__":
    main()
