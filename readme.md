# cfn-sanitizer

**cfn-sanitizer** is a lightweight Python tool that intelligently sanitizes AWS CloudFormation templates by identifying and replacing sensitive information with CloudFormation dynamic references to AWS Secrets Manager. It handles both YAML and JSON formats and can be used via CLI or as a Python library.

---

## Installation

```bash
# Editable (development) install:
pip install -e .

# Or regular install from PyPI:
pip install cfn-sanitizer
```

---

## Package Contents

```
cfn_sanitizer/
├── __init__.py           # exposes sanitize_template API
├── cli.py                # Click-based CLI entry point
├── scanner.py            # loads a .yaml/.yml/.json file into a dict
├── sanitizer.py          # core logic: smart detection and sanitization
├── utils.py              # helpers for reading/writing files & reports
└── patterns.yaml         # configurable secret-detection rules
setup.py                  # package metadata & console_scripts entry
README.md                 # this documentation file
```

---

## CLI Interface

After installation you get the **`sanitize-cfn`** command:

```bash
Usage: sanitize-cfn [OPTIONS]

  Sanitize a CloudFormation template by replacing sensitive information.

Options:
  -i, --input TEXT     Path to the CloudFormation template
                       (.yaml/.yml/.json)  [required]
  -o, --output TEXT    Path to write the sanitized template  [required]
  -r, --report TEXT    Optional path to write a JSON report
  --help               Show this message and exit.
```

**Example:**

```bash
sanitize-cfn \
  -i template.yaml \
  -o sanitized.yaml \
  -r removals.json
```

* **`-i/--input`**: path to a single CFN template file (YAML or JSON)
* **`-o/--output`**: path to write the sanitized template (same format as input)
* **`-r/--report`**: optional JSON file listing every replaced secret (`path`, `pattern`, `original`)

---

## Programmatic API

Import and call the core function in your Python code:

```python
from cfn_sanitizer import sanitize_template
import yaml, json

# 1) Load your template into a Python dict
with open("template.yaml") as f:
    tpl = yaml.safe_load(f)

# 2) Sanitize
sanitized_tpl, report = sanitize_template(tpl)

# 3a) Work with the sanitized dict in-memory
print("Replacements:", report)

# 3b) Serialize back to file
with open("sanitized.json", "w") as f:
    json.dump(sanitized_tpl, f, indent=2)
```

* **Input**: a Python `dict` representing the CFN template
* **Output**: a tuple `(sanitized_template_dict, report_list)`

  * `sanitized_template_dict`: same structure as input, with sensitive fields replaced by `{{resolve:secretsmanager:…}}`
  * `report_list`: a list of `{ "path": str, "pattern": str, "original": str }` entries

---

## Smart Detection

The sanitizer uses a multi-layered approach to identify sensitive information:

1. **Parameter Analysis**: Pre-scans all parameters to identify sensitive ones based on:
   - Parameter names containing sensitive terms (like "password", "secret", etc.)
   - NoEcho attribute set to true
   - Default value patterns matching sensitive data

2. **Intelligent Value Detection**: Avoids sanitizing non-sensitive values by:
   - Preserving instance types (e.g., t3.micro, db.r5.large)
   - Keeping simple resource names and identifiers
   - Recognizing common non-sensitive parameters

3. **Sensitive Content Scanning**: Detects sensitive data in various locations:
   - Parameter default values
   - Resource properties
   - UserData blocks (including Base64-encoded values)
   - Descriptions and other text fields

4. **Special Case Handling**:
   - Avoids sanitizing Tag Values that are simple resource names
   - Preserves environment designations (prod, dev, etc.)
   - Special detection for lists of credentials/passwords
   - Handles nested CloudFormation intrinsic functions

---

## Input & Output Formats

* **YAML**

  * Intrinsic tags like `!Ref`, `!GetAtt` are preserved.
  * Output maintains proper formatting for readability.

* **JSON**

  * Intrinsics appear as native JSON objects, e.g.

    ```json
    "MasterUserPassword": { "Ref": "DBPassword" }
    ```
  * Output uses consistent and readable indentation.

The tool detects input format from the file extension and writes output in the same format.

---

## Configuring Secret Patterns

All detection rules live in **`patterns.yaml`**. Each entry can have:

* **`keys`** (optional): a list of property names to check
* **`regex`** (optional): a pattern to match values anywhere
* **`param_name_regex`** (optional): when `keys` includes `Default`, only apply under parameters whose logical ID matches this regex
* **`description`**: human-readable label

**Example patterns:**

```yaml
patterns:
  # AWS Secret Access Keys anywhere in the template
  aws_secret_access_key:
    regex: '[A-Za-z0-9/+=]{40}'
    description: AWS Secret Access Keys

  # Only replace MasterUserPassword or DBPassword fields
  rds_master_password:
    keys:
      - MasterUserPassword
      - DBPassword
    description: RDS master user passwords

  # Only replace Default under parameters named *Password, *Secret, or *Token
  generic_password:
    keys:
      - Default
    regex: '(?=.*[A-Z])(?=.*[0-9])(?=.*[!@#$%^&*()]).*'
    param_name_regex: '.*(Password|Secret|Token).*'
    description: Default values for parameters whose names imply secrets
```

You can customize patterns to match your organization's naming conventions and security requirements.

---

## Examples

**Original template:**

```yaml
Parameters:
  DBPassword:
    Type: String
    Default: SuperSecret123!
  InstanceType:
    Type: String
    Default: t3.micro
Resources:
  MyDB:
    Type: AWS::RDS::DBInstance
    Properties:
      MasterUserPassword: !Ref DBPassword
      DBInstanceClass: !Ref InstanceType
  MyInstance:
    Type: AWS::EC2::Instance
    Properties:
      InstanceType: t3.large
      Tags:
        - Key: Name
          Value: app-server
```

**Sanitized output:**

```yaml
Parameters:
  DBPassword:
    Type: String
    Default: "{{resolve:secretsmanager:generic_password:SecretString:Default}}"
  InstanceType:
    Type: String
    Default: t3.micro
Resources:
  MyDB:
    Type: AWS::RDS::DBInstance
    Properties:
      MasterUserPassword: "{{resolve:secretsmanager:rds_master_password:SecretString:MasterUserPassword}}"
      DBInstanceClass: !Ref InstanceType
  MyInstance:
    Type: AWS::EC2::Instance
    Properties:
      InstanceType: t3.large
      Tags:
        - Key: Name
          Value: app-server
```

Note how the sanitizer correctly preserved the non-sensitive values like instance types and simple resource names.

---

## Contributing & License

* Contributions welcome! Please open issues or pull requests.
* Licensed under MIT; see `LICENSE` for details.



