"""CDK application entry point for the IaC scanner pipeline."""
#!/usr/bin/env python3
from __future__ import annotations

import aws_cdk as cdk

from .pipeline_stack import PipelineStack


def main() -> None:
    app = cdk.App()
    PipelineStack(app, "IaCScannerPipeline")
    app.synth()


if __name__ == "__main__":
    main()
