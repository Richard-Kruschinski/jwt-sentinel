import argparse
import json
import sys

from .analyzer import JwtAnalyzer, result_to_json_dict
from .config import load_config
from . import __version__


def _load_token_from_args(args):
    if args.token is not None:
        return args.token

    if args.token_file is not None:
        try:
            with open(args.token_file, "r", encoding="utf-8") as f:
                token_text = f.read()
        except OSError as exc:
            print("Error: could not read token file: {}".format(exc), file=sys.stderr)
            sys.exit(1)

        token_text = token_text.strip()
        return token_text

    print("Error: either --token or --token-file must be provided.", file=sys.stderr)
    sys.exit(1)


def _format_text_report(result):
    lines = []

    lines.append("JWT Security Report")
    lines.append("===================")
    lines.append("")

    lines.append("Algorithm        : {}".format(result.algorithm))
    lines.append("Signature valid  : {}".format(result.signature_valid))
    lines.append("Security score   : {} / 100".format(result.score))
    lines.append("")

    lines.append("Header:")
    header_json = json.dumps(result.header, indent=2, sort_keys=True)
    lines.append(header_json)
    lines.append("")

    lines.append("Payload:")
    payload_json = json.dumps(result.payload, indent=2, sort_keys=True)
    lines.append(payload_json)
    lines.append("")

    lines.append("Findings:")

    if len(result.findings) == 0:
        lines.append("  None. No rules fired (this does not guarantee security).")
    else:
        for finding in result.findings:
            severity = finding.severity.upper()
            line = "  - [{}] {} (id={})".format(severity, finding.title, finding.id)
            lines.append(line)
            lines.append("      {}".format(finding.description))
            lines.append("      Recommendation: {}".format(finding.recommendation))

    text = "\n".join(lines)
    return text


def build_arg_parser():
    parser = argparse.ArgumentParser(
        prog="jwt-sentinel",
        description="JWT Security Analyzer – inspect JSON Web Tokens for common security issues.",
    )

    parser.add_argument(
        "--version",
        action="version",
        version="jwt-sentinel {}".format(__version__),
    )

    parser.add_argument(
        "--token",
        help="JWT string to analyse.",
    )

    parser.add_argument(
        "--token-file",
        help="Path to a file containing the JWT.",
    )

    parser.add_argument(
        "--secret",
        help="Secret or key to verify the signature.",
    )

    parser.add_argument(
        "--config",
        help="Path to a JSON config file to override defaults.",
    )

    parser.add_argument(
        "--output",
        choices=["text", "json"],
        default="text",
        help="Output format. Defaults to 'text'.",
    )

    return parser


def main(argv=None):
    parser = build_arg_parser()
    args = parser.parse_args(argv)

    token = _load_token_from_args(args)

    try:
        config = load_config(args.config)
    except Exception as exc:
        print("Error loading config: {}".format(exc), file=sys.stderr)
        sys.exit(1)

    analyzer = JwtAnalyzer(config)

    try:
        result = analyzer.analyze(token, secret=args.secret)
    except Exception as exc:
        print("Error analysing token: {}".format(exc), file=sys.stderr)
        sys.exit(1)

    if args.output == "json":
        data = result_to_json_dict(result)
        json_text = json.dumps(data, indent=2, sort_keys=True)
        print(json_text)
    else:
        report = _format_text_report(result)
        print(report)
