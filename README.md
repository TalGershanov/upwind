# Phishing Detector

Scans an email for phishing indicators and returns a verdict with reasons.
Runs on AWS: CloudFront → ALB → 2× EC2 (Auto Scaling Group) → RDS PostgreSQL. Built with Terraform.

**Web UI**

<img src="screenshots/app.jpg" width="700" alt="Web UI: uploaded email, PHISHING verdict with indicators">

**Gmail add-on**

<img src="screenshots/gmail.webp" width="700" alt="Gmail add-on card with verdict and indicators">

---

## Code layers

```mermaid
flowchart TB
    subgraph CL["Clients"]
        UI["Web UI<br/>api/static/index.html"]
        GM["Gmail add-on<br/>gmail/Code.gs"]
    end
    subgraph API["api/ · FastAPI · gunicorn + uvicorn"]
        EP["main.py<br/>POST /api/analyze"]
        HC["main.py<br/>/health · /health/deep"]
    end
    subgraph LOGIC["logic/"]
        PA["email_parser.py"]
        IND["indicators.py<br/>@indicator registry"]
        SC["scoring.py"]
        HLP["config.py · domains.py<br/>attachments.py · data/"]
    end
    subgraph DAL["dal/"]
        HS["history_store.py<br/>HistoryStore interface"]
        DC["db_config.py"]
        RS["rds_store.py · models.py<br/>SQLAlchemy"]
    end
    subgraph ROOT["Root files and folders"]
        LG["logging_config.py"]
        RQ["requirements.txt<br/>requirements-dev.txt"]
        GI[".gitignore · README.md"]
        TS["tests/ · pytest"]
        TF["terraform/<br/>zips api, dal, logic → S3"]
    end
    DB[("RDS PostgreSQL")]
    SM["Secrets Manager"]

    UI -- upload --> EP
    GM -- upload --> EP
    EP -- parse --> PA
    EP -- analyze --> IND
    IND --> SC
    IND -.-> HLP
    IND -- history --> HS
    HS -- implemented by --> RS
    RS -- "SQL · TLS" --> DB
    EP -- startup --> DC
    DC -- builds --> RS
    DC -- credentials --> SM
    HC -- ping --> RS
    EP -- startup --> LG
    LG ~~~ RQ ~~~ GI ~~~ TS ~~~ TF
```

---

## Indicators

Each indicator scores 1–4. The verdict is the weighted average:
`< 1.75` NOT_PHISHING · `< 2.5` PROBABLY_NOT_PHISHING · `< 3.25` PROBABLY_PHISHING · else PHISHING.
A sender already on the blocklist returns BLOCKLIST with its saved report.

| Indicator | Weight | Logic |
|---|---|---|
| Sender Authentication | 0.20 | SPF / DKIM / DMARC from the top `Authentication-Results` header, only if a trusted server added it |
| Suspicious links | 0.20 | Per URL: IP host, `user@`, shortener, cheap TLD, many subdomains, punycode, odd port. |
| Spoofed sender | 0.25 | Known brand in the sender domain or display name, same name on another TLD, or a look-alike (edit distance ≤ 2) |
| Suspicious wording | 0.10 | Urgency, credentials, payment, threat and prize phrases (English and Hebrew); more categories = higher score |
| Attachment analysis | 0.20 | Executables, double extensions, macro documents, MIME mismatch, risky zips (metadata only, never extracted) |
| Sender history | 0.05 | Sender reputation in RDS: first seen, mostly phishing, or allowlisted after 3 clean authenticated messages |

### Add an indicator

Only new code is needed, in `logic/indicators.py`:

1. Write a function `(context: EmailContext) -> IndicatorResult`.
2. Decorate it with `@indicator('Name', weight=...)`. Weights are relative.
3. Return `IndicatorResult(score, reasons, details)` with a score from `config` (1–4).

The registry, scoring, report, UI and Gmail card pick it up. Word and domain lists go in `logic/config.py`.

---

## AWS infrastructure

```mermaid
%%{init: {"flowchart": {"rankSpacing": 90, "nodeSpacing": 70, "padding": 20}}}%%
flowchart TB
    User([User]) --> CF[CloudFront<br/>outside the VPC]

    subgraph VPC["VPC 10.0.0.0/16"]
        subgraph Public["Public subnets<br/>10.0.1.0/24 and 10.0.2.0/24"]
            ALB[ALB]
            NAT[NAT Gateway<br/>AZ-a only]
        end

        subgraph Private["Private subnets<br/>10.0.11.0/24 and 10.0.12.0/24"]
            EC2[EC2 app x2<br/>port 8000]
            RDS[(RDS PostgreSQL<br/>port 5432)]
        end
    end

    CF --> ALB
    ALB --> EC2
    EC2 --> RDS
    EC2 -.-> NAT
```



---

## Monitoring
# built a dashboard - widgets for a business-y perspective:

<img src="screenshots/business.webp" width="800" alt="Dashboard business overview: emails analyzed, phishing rate, verdict mix, alarms">

# and monitoring - look below
<img src="screenshots/monitoring.webp" width="800" alt="Dashboard: target group health, ASG instances, CPU, memory, disk, app errors">

---

## Availability

- **2 Availability Zones**
- **Stateless app**:  
- **Application Load Balancer**

<img src="screenshots/lb.webp" width="800" alt="Analyses per instance: both instances receive traffic">

*Both instances handle requests, and each writes to its own log stream.*

- **Auto Scaling Group** (min = max = 2): a failed instance is replaced automatically, code updates roll through with at least 50% healthy.


<img src="screenshots/autoscale.webp" width="800" alt="An instance was terminated by hand and the ASG launched a replacement">

*An instance was terminated by hand: in service dropped from 2 to 1, the ASG launched a replacement, and the events table shows Terminate and Launch.*



---

## Permissions

```mermaid
flowchart LR
    EC2["EC2 instances<br/>IAM role"]

    subgraph IAM["permission -> unlocks"]
        P1["AmazonSSMManagedInstanceCore"]
        P2["CloudWatchAgentServerPolicy"]
        P3["secretsmanager:GetSecretValue<br/>this one secret only"]
        P4["s3:GetObject<br/>artifacts bucket only"]
    end

    EC2 --> IAM
    P1 --> SSM["SSM Session Manager"]
    P2 --> CW["CloudWatch"]
    P3 --> SMG["Secrets Manager<br/>RDS master secret<br/>read on every new DB connection"]
    P4 --> S3["S3 artifacts"]

    subgraph SGS["Security groups · each tier accepts only the tier above"]
        direction LR
        CFP["CloudFront<br/>prefix list"] --> ALBSG["alb-sg"]
        ALBSG --> APPSG["app-sg"]
        APPSG --> DBSG["db-sg"]
        APPSG  --> VPCESG["vpce-sg"]
    end
```


---

## Reliability

| Failure | How it is handled | Where to see it |
|---|---|---|
| Bad upload (empty, over 5 MB, not an email) | 400 / 413, logged as a warning, the API keeps running | `EmailsRejected` metric, *Emails rejected* widgets |
| Exception in the app | Logged as `ERROR` | `AppErrors` metric, alarm over 5 in 5 min |
| 5XX from the app or the ALB | Counted by the ALB | Alarms `target-5xx`, `elb-5xx`; *Responses by status*, *Error rate %*, *Recent 4XX/5XX requests* |
| Slow responses | Latency percentiles | Alarm `response-time-p95` over 1 s; *Response time* widget |
| Database unreachable | Short timeouts (connect 5 s, pool 10 s), pre-ping, `/health/deep` returns 503 | `AppErrors`, alarms `rds-cpu`, `rds-free-storage` |
| Two instances boot together | `create_schema` takes a DB lock and retries 5 times | `/phishing-detector/boot` log group |

| Monitoring itself fails | CloudWatch agent is installed last and its failure never blocks the app | Boot log |

Every alarm notifies the SNS email topic. Logs are kept 14 days and rotated on disk.

---

## Security

Layers, outermost to innermost:

```mermaid
flowchart TB
    subgraph L1["1 · HTTPS at CloudFront"]
        subgraph L2["2 · ALB: only the CloudFront prefix list, secret header, default 403"]
            subgraph L3["3 · VPC private subnets: no public IPs, no SSH, outbound only through NAT"]
                subgraph L4["4 · app-sg: ALB only · least-privilege IAM role "]
                    APP["EC2 · EBS encrypted with KMS<br/>DB password from Secrets Manager<br/>(KMS-encrypted, never on disk)"]
                    subgraph L5["5 · db-sg: app-sg only"]
                        DB[("RDS<br/>encrypted with KMS ")]
                    end
                end
            end
        end
    end
```

Also: S3 buckets encrypted (SSE-S3) with all public access blocked · CloudTrail audit of every API call · attachments are analysed statically and never executed · uploads capped at 5 MB.

CloudFront talks to the ALB over HTTP (no custom domain, so no certificate); the ALB only accepts it from CloudFront.


---

## Deploy 

```bash
# RDS "phishing-detector-db" is created by hand first. Confirm the SNS email afterwards.
terraform apply -var alert_email=you@example.com
```
## for the gmail add-on: 
#### update the new url in script.google.com -> nav to project -> project settings -> Script Properties



