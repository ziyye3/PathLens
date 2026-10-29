window.PATHLENS_DEMO = {
  "schema_version": "1.0",
  "domain": "example.com",
  "observed_at": "2026-10-14T00:00:00Z",
  "generated_at": "2026-10-29T19:12:43.798390Z",
  "collection_mode": "snapshot",
  "assets": [
    {
      "name": "missing.example.com",
      "discovered_by": [
        "crt.sh",
        "dns"
      ],
      "discovery_evidence": [
        {
          "source": "crt.sh",
          "description": "Name observed in certificate records: missing.example.com",
          "observed_at": "2026-10-14T00:00:00Z",
          "reference": "https://crt.sh/"
        },
        {
          "source": "dns",
          "description": "missing.example.com CNAME: removed.us-east-1.elasticbeanstalk.com; resolver 1.1.1.1",
          "observed_at": "2026-10-14T00:00:00Z",
          "reference": null
        }
      ],
      "cname_chain": [
        "missing.example.com",
        "removed.us-east-1.elasticbeanstalk.com"
      ],
      "addresses": [],
      "priority": "high",
      "findings": [
        {
          "rule_id": "dangling-known-service",
          "priority": "high",
          "title": "Known service alias with an NXDOMAIN target",
          "explanation": "A CNAME target associated with a known service did not resolve. This is a review candidate, not proof of takeover.",
          "action": "Verify the DNS record and resource ownership before removing or changing anything.",
          "evidence": [
            {
              "source": "dns",
              "description": "missing.example.com CNAME: removed.us-east-1.elasticbeanstalk.com; resolver 1.1.1.1",
              "observed_at": "2026-10-14T00:00:00Z",
              "reference": null
            },
            {
              "source": "dns",
              "description": "removed.us-east-1.elasticbeanstalk.com CNAME: NXDOMAIN; resolver 1.1.1.1",
              "observed_at": "2026-10-14T00:00:00Z",
              "reference": null
            },
            {
              "source": "service-reference",
              "description": "AWS Elastic Beanstalk: removed.us-east-1.elasticbeanstalk.com",
              "observed_at": null,
              "reference": "https://github.com/EdOverflow/can-i-take-over-xyz"
            }
          ]
        },
        {
          "rule_id": "known-service-review",
          "priority": "medium",
          "title": "Alias points to a service with documented takeover considerations",
          "explanation": "The service is in the review list. DNS alone cannot show whether a resource is unclaimed.",
          "action": "Verify that the DNS alias and the corresponding resource are both owned and configured correctly.",
          "evidence": [
            {
              "source": "dns",
              "description": "missing.example.com CNAME: removed.us-east-1.elasticbeanstalk.com; resolver 1.1.1.1",
              "observed_at": "2026-10-14T00:00:00Z",
              "reference": null
            },
            {
              "source": "service-reference",
              "description": "AWS Elastic Beanstalk: removed.us-east-1.elasticbeanstalk.com",
              "observed_at": null,
              "reference": "https://github.com/EdOverflow/can-i-take-over-xyz"
            }
          ]
        },
        {
          "rule_id": "aws-infrastructure",
          "priority": "info",
          "title": "AWS infrastructure indication",
          "explanation": "A CNAME or IP address matches an AWS indicator. This does not establish asset ownership or a vulnerability.",
          "action": "Verify ownership and whether this externally visible service is intended.",
          "evidence": [
            {
              "source": "dns",
              "description": "missing.example.com CNAME: removed.us-east-1.elasticbeanstalk.com; resolver 1.1.1.1",
              "observed_at": "2026-10-14T00:00:00Z",
              "reference": null
            },
            {
              "source": "service-reference",
              "description": "AWS Elastic Beanstalk: removed.us-east-1.elasticbeanstalk.com",
              "observed_at": null,
              "reference": "https://github.com/EdOverflow/can-i-take-over-xyz"
            }
          ]
        }
      ],
      "warnings": [],
      "threat_context": [
        {
          "id": "aws-elastic-beanstalk-dangling-alias",
          "title": "Review an Elastic Beanstalk DNS alias",
          "description": "AWS warns that an available hostname can be reused after an environment is terminated and advises removing stale DNS mappings.",
          "applicability": "An Elastic Beanstalk alias was observed; the environment state and ownership have not been checked.",
          "action": "Verify the environment and DNS mapping; remove stale mappings when appropriate.",
          "limitations": "An NXDOMAIN answer or a service match alone does not prove that the environment is terminated or reusable.",
          "source_name": "AWS Elastic Beanstalk documentation",
          "source_url": "https://docs.aws.amazon.com/elasticbeanstalk/latest/dg/customdomains.html",
          "reviewed_at": "2026-10-30",
          "matched_rule_id": "known-service-review"
        }
      ],
      "indicator_matches": [],
      "vulnerability_matches": [],
      "product_kev_candidates": [],
      "osv_matches": [],
      "exposure_claims": []
    },
    {
      "name": "s3.example.com",
      "discovered_by": [
        "crt.sh",
        "dns"
      ],
      "discovery_evidence": [
        {
          "source": "crt.sh",
          "description": "Name observed in certificate records: s3.example.com",
          "observed_at": "2026-10-14T00:00:00Z",
          "reference": "https://crt.sh/"
        },
        {
          "source": "dns",
          "description": "s3.example.com CNAME: s3.example.com.s3.us-east-1.amazonaws.com; resolver 1.1.1.1",
          "observed_at": "2026-10-14T00:00:00Z",
          "reference": null
        }
      ],
      "cname_chain": [
        "s3.example.com",
        "s3.example.com.s3.us-east-1.amazonaws.com"
      ],
      "addresses": [],
      "priority": "medium",
      "findings": [
        {
          "rule_id": "known-service-review",
          "priority": "medium",
          "title": "Alias points to a service with documented takeover considerations",
          "explanation": "The service is in the review list. DNS alone cannot show whether a resource is unclaimed.",
          "action": "Verify that the DNS alias and the corresponding resource are both owned and configured correctly.",
          "evidence": [
            {
              "source": "dns",
              "description": "s3.example.com CNAME: s3.example.com.s3.us-east-1.amazonaws.com; resolver 1.1.1.1",
              "observed_at": "2026-10-14T00:00:00Z",
              "reference": null
            },
            {
              "source": "service-reference",
              "description": "AWS S3: s3.example.com.s3.us-east-1.amazonaws.com",
              "observed_at": null,
              "reference": "https://docs.aws.amazon.com/AmazonS3/latest/userguide/VirtualHosting.html"
            }
          ]
        },
        {
          "rule_id": "aws-infrastructure",
          "priority": "info",
          "title": "AWS infrastructure indication",
          "explanation": "A CNAME or IP address matches an AWS indicator. This does not establish asset ownership or a vulnerability.",
          "action": "Verify ownership and whether this externally visible service is intended.",
          "evidence": [
            {
              "source": "dns",
              "description": "s3.example.com CNAME: s3.example.com.s3.us-east-1.amazonaws.com; resolver 1.1.1.1",
              "observed_at": "2026-10-14T00:00:00Z",
              "reference": null
            },
            {
              "source": "service-reference",
              "description": "AWS S3: s3.example.com.s3.us-east-1.amazonaws.com",
              "observed_at": null,
              "reference": "https://docs.aws.amazon.com/AmazonS3/latest/userguide/VirtualHosting.html"
            }
          ]
        }
      ],
      "warnings": [],
      "threat_context": [
        {
          "id": "aws-s3-dangling-alias",
          "title": "Review an S3 DNS alias and its matching bucket",
          "description": "A DNS alias that points to S3 without a matching bucket can permit another AWS user to create that bucket and publish content under the alias.",
          "applicability": "An S3 alias was observed; the existence or ownership of a matching bucket has not been checked.",
          "action": "Verify the matching bucket and its owner; remove or change stale aliases when appropriate.",
          "limitations": "DNS observations alone cannot determine whether a matching bucket exists or whether takeover is possible.",
          "source_name": "AWS S3 documentation",
          "source_url": "https://docs.aws.amazon.com/AmazonS3/latest/userguide/VirtualHosting.html",
          "reviewed_at": "2026-10-30",
          "matched_rule_id": "known-service-review"
        }
      ],
      "indicator_matches": [],
      "vulnerability_matches": [],
      "product_kev_candidates": [],
      "osv_matches": [],
      "exposure_claims": []
    },
    {
      "name": "timeout.example.com",
      "discovered_by": [
        "crt.sh",
        "dns"
      ],
      "discovery_evidence": [
        {
          "source": "crt.sh",
          "description": "Name observed in certificate records: timeout.example.com",
          "observed_at": "2026-10-14T00:00:00Z",
          "reference": "https://crt.sh/"
        },
        {
          "source": "dns",
          "description": "timeout.example.com CNAME: unverified.elasticbeanstalk.com; resolver 1.1.1.1",
          "observed_at": "2026-10-14T00:00:00Z",
          "reference": null
        }
      ],
      "cname_chain": [
        "timeout.example.com",
        "unverified.elasticbeanstalk.com"
      ],
      "addresses": [],
      "priority": "medium",
      "findings": [
        {
          "rule_id": "known-service-review",
          "priority": "medium",
          "title": "Alias points to a service with documented takeover considerations",
          "explanation": "The service is in the review list. DNS alone cannot show whether a resource is unclaimed.",
          "action": "Verify that the DNS alias and the corresponding resource are both owned and configured correctly.",
          "evidence": [
            {
              "source": "dns",
              "description": "timeout.example.com CNAME: unverified.elasticbeanstalk.com; resolver 1.1.1.1",
              "observed_at": "2026-10-14T00:00:00Z",
              "reference": null
            },
            {
              "source": "service-reference",
              "description": "AWS Elastic Beanstalk: unverified.elasticbeanstalk.com",
              "observed_at": null,
              "reference": "https://github.com/EdOverflow/can-i-take-over-xyz"
            }
          ]
        },
        {
          "rule_id": "aws-infrastructure",
          "priority": "info",
          "title": "AWS infrastructure indication",
          "explanation": "A CNAME or IP address matches an AWS indicator. This does not establish asset ownership or a vulnerability.",
          "action": "Verify ownership and whether this externally visible service is intended.",
          "evidence": [
            {
              "source": "dns",
              "description": "timeout.example.com CNAME: unverified.elasticbeanstalk.com; resolver 1.1.1.1",
              "observed_at": "2026-10-14T00:00:00Z",
              "reference": null
            },
            {
              "source": "service-reference",
              "description": "AWS Elastic Beanstalk: unverified.elasticbeanstalk.com",
              "observed_at": null,
              "reference": "https://github.com/EdOverflow/can-i-take-over-xyz"
            }
          ]
        }
      ],
      "warnings": [
        "Some DNS queries failed or timed out; absence cannot be established."
      ],
      "threat_context": [
        {
          "id": "aws-elastic-beanstalk-dangling-alias",
          "title": "Review an Elastic Beanstalk DNS alias",
          "description": "AWS warns that an available hostname can be reused after an environment is terminated and advises removing stale DNS mappings.",
          "applicability": "An Elastic Beanstalk alias was observed; the environment state and ownership have not been checked.",
          "action": "Verify the environment and DNS mapping; remove stale mappings when appropriate.",
          "limitations": "An NXDOMAIN answer or a service match alone does not prove that the environment is terminated or reusable.",
          "source_name": "AWS Elastic Beanstalk documentation",
          "source_url": "https://docs.aws.amazon.com/elasticbeanstalk/latest/dg/customdomains.html",
          "reviewed_at": "2026-10-30",
          "matched_rule_id": "known-service-review"
        }
      ],
      "indicator_matches": [],
      "vulnerability_matches": [],
      "product_kev_candidates": [],
      "osv_matches": [],
      "exposure_claims": []
    },
    {
      "name": "cdn.example.com",
      "discovered_by": [
        "crt.sh",
        "dns"
      ],
      "discovery_evidence": [
        {
          "source": "crt.sh",
          "description": "Name observed in certificate records: cdn.example.com",
          "observed_at": "2026-10-14T00:00:00Z",
          "reference": "https://crt.sh/"
        },
        {
          "source": "dns",
          "description": "cdn.example.com CNAME: demo.cloudfront.net; resolver 1.1.1.1",
          "observed_at": "2026-10-14T00:00:00Z",
          "reference": null
        }
      ],
      "cname_chain": [
        "cdn.example.com",
        "demo.cloudfront.net"
      ],
      "addresses": [
        "203.0.113.10"
      ],
      "priority": "info",
      "findings": [
        {
          "rule_id": "aws-infrastructure",
          "priority": "info",
          "title": "AWS infrastructure indication",
          "explanation": "A CNAME or IP address matches an AWS indicator. This does not establish asset ownership or a vulnerability.",
          "action": "Verify ownership and whether this externally visible service is intended.",
          "evidence": [
            {
              "source": "dns",
              "description": "cdn.example.com CNAME: demo.cloudfront.net; resolver 1.1.1.1",
              "observed_at": "2026-10-14T00:00:00Z",
              "reference": null
            },
            {
              "source": "service-reference",
              "description": "AWS CloudFront: demo.cloudfront.net",
              "observed_at": null,
              "reference": "https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/CNAMEs.html"
            },
            {
              "source": "dns",
              "description": "demo.cloudfront.net A: 203.0.113.10; resolver 1.1.1.1",
              "observed_at": "2026-10-14T00:00:00Z",
              "reference": null
            },
            {
              "source": "aws-ip-ranges",
              "description": "203.0.113.10 is in 203.0.113.0/24 (EXAMPLE, TEST); AWS list date: 2026-10-14-00-00-00",
              "observed_at": null,
              "reference": "https://docs.aws.amazon.com/vpc/latest/userguide/aws-ip-ranges.html"
            }
          ]
        }
      ],
      "warnings": [],
      "threat_context": [],
      "indicator_matches": [],
      "vulnerability_matches": [],
      "product_kev_candidates": [],
      "osv_matches": [],
      "exposure_claims": []
    },
    {
      "name": "ip.example.com",
      "discovered_by": [
        "crt.sh",
        "dns"
      ],
      "discovery_evidence": [
        {
          "source": "crt.sh",
          "description": "Name observed in certificate records: ip.example.com",
          "observed_at": "2026-10-14T00:00:00Z",
          "reference": "https://crt.sh/"
        },
        {
          "source": "dns",
          "description": "ip.example.com A: 203.0.113.20; resolver 1.1.1.1",
          "observed_at": "2026-10-14T00:00:00Z",
          "reference": null
        }
      ],
      "cname_chain": [
        "ip.example.com"
      ],
      "addresses": [
        "203.0.113.20"
      ],
      "priority": "info",
      "findings": [
        {
          "rule_id": "aws-infrastructure",
          "priority": "info",
          "title": "AWS infrastructure indication",
          "explanation": "A CNAME or IP address matches an AWS indicator. This does not establish asset ownership or a vulnerability.",
          "action": "Verify ownership and whether this externally visible service is intended.",
          "evidence": [
            {
              "source": "dns",
              "description": "ip.example.com A: 203.0.113.20; resolver 1.1.1.1",
              "observed_at": "2026-10-14T00:00:00Z",
              "reference": null
            },
            {
              "source": "aws-ip-ranges",
              "description": "203.0.113.20 is in 203.0.113.0/24 (EXAMPLE, TEST); AWS list date: 2026-10-14-00-00-00",
              "observed_at": null,
              "reference": "https://docs.aws.amazon.com/vpc/latest/userguide/aws-ip-ranges.html"
            }
          ]
        }
      ],
      "warnings": [],
      "threat_context": [],
      "indicator_matches": [],
      "vulnerability_matches": [],
      "product_kev_candidates": [],
      "osv_matches": [],
      "exposure_claims": []
    },
    {
      "name": "example.com",
      "discovered_by": [
        "crt.sh",
        "user input"
      ],
      "discovery_evidence": [
        {
          "source": "user-input",
          "description": "Requested domain: example.com",
          "observed_at": null,
          "reference": null
        },
        {
          "source": "crt.sh",
          "description": "Name observed in certificate records: example.com",
          "observed_at": "2026-10-14T00:00:00Z",
          "reference": "https://crt.sh/"
        }
      ],
      "cname_chain": [
        "example.com"
      ],
      "addresses": [],
      "priority": "unknown",
      "findings": [],
      "warnings": [
        "No DNS observations for this name; its status is unknown."
      ],
      "threat_context": [],
      "indicator_matches": [],
      "vulnerability_matches": [],
      "product_kev_candidates": [],
      "osv_matches": [],
      "exposure_claims": []
    }
  ],
  "warnings": [
    "Synthetic sample only: the reserved example address range is not an actual AWS range."
  ],
  "limitations": [
    "Public DNS and certificates do not prove asset ownership or the existence of a vulnerability.",
    "A DNS candidate is not proof that a cloud resource can be claimed; no HTTP fingerprint is checked.",
    "Public recursive DNS lookups may be forwarded to authoritative name servers.",
    "AWS IP ranges do not cover every AWS address or prove the end customer; data may be stale.",
    "Indicator matches are contextual leads, not evidence of compromise or attribution. Shared cloud IPs and stale indicators can cause false positives.",
    "Complex STIX results use supplied indicators and DNS observations only. A match across observations does not establish a relationship or compromise; missing or unsupported data and matcher limitations require review."
  ],
  "threat_feed": {
    "status": "not_supplied",
    "source_name": null,
    "source_url": null,
    "generated_at": null,
    "indicator_count": 0,
    "match_count": 0
  },
  "stix_correlation": {
    "status": "loaded",
    "provenance": "user_supplied",
    "observation_count": 5,
    "match_count": 2,
    "indeterminate_count": 0,
    "results": [
      {
        "indicator_id": "indicator--00000000-0000-4000-8000-000000000003",
        "status": "matched",
        "indicator_status": "active",
        "reason": null,
        "evidence": [
          {
            "observation_id": "observed-data--d3f5dc2a-b354-5aa9-ab1a-77f7eaec3c75",
            "dns_record_index": 2,
            "name": "cdn.example.com",
            "record_type": "CNAME",
            "values": [
              "demo.cloudfront.net"
            ],
            "observed_at": "2026-10-14T00:00:00Z"
          }
        ]
      },
      {
        "indicator_id": "indicator--00000000-0000-4000-8000-000000000004",
        "status": "matched",
        "indicator_status": "active",
        "reason": null,
        "evidence": [
          {
            "observation_id": "observed-data--5e6bdc0e-65ae-593c-81e3-95172ae77bc6",
            "dns_record_index": 7,
            "name": "ip.example.com",
            "record_type": "A",
            "values": [
              "203.0.113.20"
            ],
            "observed_at": "2026-10-14T00:00:00Z"
          },
          {
            "observation_id": "observed-data--d3f5dc2a-b354-5aa9-ab1a-77f7eaec3c75",
            "dns_record_index": 2,
            "name": "cdn.example.com",
            "record_type": "CNAME",
            "values": [
              "demo.cloudfront.net"
            ],
            "observed_at": "2026-10-14T00:00:00Z"
          }
        ]
      }
    ]
  },
  "cve_correlation": {
    "status": "not_supplied",
    "catalog_version": null,
    "observation_count": 0,
    "match_count": 0
  },
  "product_correlation": {
    "status": "not_supplied",
    "catalog_version": null,
    "observation_count": 0,
    "candidate_count": 0
  },
  "osv_correlation": {
    "status": "not_supplied",
    "query_count": 0,
    "match_count": 0,
    "queried_at": null
  },
  "exposure_correlation": {
    "status": "not_supplied",
    "observation_count": 0,
    "match_count": 0
  }
};

