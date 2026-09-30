from collections import defaultdict
from datetime import datetime
import csv
import os
import re
import sys


def parse_arguments() -> tuple[str, str]:
    """
    Parse command-line arguments and validate the input log file path.

    Returns:
        tuple[str, str]: Input log file path and output CSV file path.
    """
    if len(sys.argv) < 3:
        sys.exit(
            "Не хватает аргументов. "
            "Использование: script.py <input_log> <output_csv>"
        )

    if len(sys.argv) > 3:
        sys.exit(
            f"Лишние аргументы: {sys.argv[3:]}. "
            "Использование: script.py <input_log> <output_csv>"
        )

    input_log: str = sys.argv[1]
    output_csv: str = sys.argv[2]

    if not os.path.exists(input_log):
        sys.exit(f"Файл не найден: {input_log}")

    return input_log, output_csv


def process_log(filename: str) -> tuple[list[list[str | int]], dict[str, int]]:
    """
    Read the Nginx log file, filter 5xx responses, and aggregate records.

    Args:
        filename: Path to the Nginx access log.

    Returns:
        tuple: Aggregated 5xx records and processing statistics.
    """
    result_line_log: list[list[str]] = []
    stats: dict[str, int] = {}

    with open(filename, "r", encoding="utf-8") as file:
        for line in file:
            result: list[str] = []
            d = parse_log_line(line)
            stats["processed"] = stats.get("processed", 0) + 1

            if 500 <= int(d["status"]) < 600:
                stats["5xx"] = stats.get("5xx", 0) + 1
                request = normalize_uri(d["request"])

                test_time = datetime.strptime(d["date"], "[%d/%b/%Y:%H:%M:%S]")
                formatted_date = test_time.strftime("%Y-%m-%d %H:%M:%S")

                result.append(formatted_date)
                result.append(d["ip"])
                result.append(request)
                result.append(d["status"])

            if result:
                result_line_log.append(result)

    return aggregate_records(result_line_log), stats


def parse_log_line(line: str) -> dict[str, str | dict[str, str]]:
    """
    Parse a single Nginx access log line.

    Args:
        line: Raw log line.

    Returns:
        dict: Parsed IP address, date, request data, and HTTP status code.
    """
    result: dict[str, str | dict[str, str]] = {}

    result["ip"] = re.search(
        r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
        line,
    ).group()

    result["date"] = re.search(
        r"\[\d{2}/[A-Za-z]{3}/\d{4}:\d{2}:\d{2}:\d{2}\]",
        line,
    ).group()

    result["request"] = re.search(
        r'"(?P<method>[A-Z]+)\s+(?P<target>\S+)\s+(?P<version>HTTP/\d\.\d)"',
        line,
    ).groupdict()

    result["status"] = line.split('"-"')[0].split()[-1]

    return result


def normalize_uri(request: dict[str, str]) -> str:
    """
    Remove the query string from the request URI.

    Args:
        request: Parsed HTTP request data.

    Returns:
        str: Normalized URI without query parameters.
    """
    return request["target"].split("?")[0]


def aggregate_records(rows: list[list[str]]) -> list[list[str | int]]:
    """
    Aggregate matching 5xx records and count their occurrences.

    Args:
        rows: Parsed records containing timestamp, IP, URI, and status.

    Returns:
        list: Aggregated records with occurrence count.
    """
    agg: dict[tuple[str, str, str], dict[str, str | int | None]] = defaultdict(
        lambda: {
            "count": 0,
            "last_timestamp": None,
        }
    )

    for timestamp, ip, uri, status in rows:
        key = (ip, uri, status)
        agg[key]["count"] = int(agg[key]["count"]) + 1
        last_timestamp = agg[key]["last_timestamp"]

        if last_timestamp is None or timestamp > str(last_timestamp):
            agg[key]["last_timestamp"] = timestamp

    result: list[list[str | int]] = []

    for (ip, uri, status), data in agg.items():
        result.append(
            [
                str(data["last_timestamp"]),
                ip,
                uri,
                status,
                int(data["count"]),
            ]
        )

    result.sort(
        key=lambda row: int(row[4]),
        reverse=True,
    )

    return result


def write_csv(
    output_file: str,
    aggregate_data: list[list[str | int]],
) -> None:
    """
    Write aggregated log records to a CSV file.

    Args:
        output_file: Path to the output CSV file.
        aggregate_data: Aggregated records to write.
    """
    with open(
        output_file,
        "w",
        encoding="utf-8",
        newline="",
    ) as file:
        writer = csv.writer(file)
        writer.writerow(["timestamp", "ip", "uri", "status", "count"])

        for row in aggregate_data:
            writer.writerow(row)


def main() -> int:
    """
    Run the log analyzer workflow.

    Returns:
        int: Process exit code.
    """
    input_log, output_csv = parse_arguments()
    aggregated_data, stats = process_log(input_log)

    write_csv(output_csv, aggregated_data)

    print(f"Processed lines: {stats['processed']}")
    print(f"5xx records found: {stats.get('5xx', 0)}")
    print(f"Report written to: {output_csv}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
