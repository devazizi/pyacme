import json
import os


def get_certificate_list(base_dir):
    certificates = []
    id = 0
    for root, dirs, files in os.walk(base_dir):
        if "certificate.json" in files:
            cert_path = os.path.join(root, "certificate.json")
            try:
                with open(cert_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    certificates.append(
                        [
                            id,
                            data.get("domain"),
                            data.get("certificate_path"),
                            data.get("expiry_date"),
                            data.get("status"),
                            data.get("renew_command"),
                            data.get("last_renewed"),
                        ]
                    )
                    id += 1
            except json.JSONDecodeError as err:
                raise err
            except Exception as e:
                raise e

    return certificates


# def get_certificate_full_details():
#     for root, dirs, files in os.walk(base_dir):
#         if "certificate.json" in files:
#             cert_path = os.path.join(root, "certificate.json")
#             try:
#                 with open(cert_path, "r", encoding="utf-8") as f:
#                     data = json.load(f)
#                     certificates.append([
#                         id,
#                         data.get('domain'),
#                         data.get('certificate_path'),
#                         data.get('expiry_date'),
#                         data.get('status'),
#                         data.get('renew_command'),
#                         data.get('last_renewed'),
#                     ])
#                     id += 1
#             except json.JSONDecodeError as err:
#                 raise err
#             except Exception as e:
#                 raise e
#
#     return certificates
