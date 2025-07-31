import argparse
import json
import logging
from analyzer.fetcher import fetch_iam_data
from analyzer.analyzer import analyze_all_policies
from analyzer.reporter import export_to_csv, export_to_json, print_summary_to_terminal

def main():
    """
    Main function to orchestrate the IAM policy analysis.
    """
    parser = argparse.ArgumentParser(description='Analyze AWS IAM policies.')
    parser.add_argument(
        '--output-format',
        choices=['json', 'csv'],
        default='json',
    )
    parser.add_argument(
        '-v', '--verbose',
        action='count',
        default=0,
    )
    args = parser.parse_args()

    # Set up logging
    log_level = logging.WARNING
    if args.verbose == 1:
        log_level = logging.INFO
    elif args.verbose >= 2:
        log_level = logging.DEBUG
    logging.basicConfig(level=log_level, format='%(asctime)s - %(levelname)s - %(message)s')

    logging.info('Starting IAM policy analysis...')

    # Fetch IAM data
    logging.info('Fetching IAM data...')
    iam_data = fetch_iam_data()
    if not iam_data:
        logging.error('Failed to fetch IAM data. Exiting.')
        return

    # Analyze IAM data
    logging.info('Analyzing IAM policies...')
    analysis_results = analyze_all_policies(iam_data)

    # Display summary to terminal
    print_summary_to_terminal(analysis_results)

    # Report results
    logging.info('Generating report...')
    if args.output_format == 'csv':
        export_to_csv(analysis_results, 'iam_analysis_results.csv')
        print('Analysis complete. Results saved to iam_analysis_results.csv')
    else:
        export_to_json(analysis_results, 'iam_analysis_results.json')
        print('Results saved to iam_analysis_results.json')

    logging.info('IAM policy analysis finished.')

if __name__ == '__main__':
    main()
