#!/usr/bin/python3

import sys
import logging
import json
import re
import os
import time
import datetime
import glob
import argparse
import configparser
import requests
import dateparser
from fuzzywuzzy import fuzz


def login(server, username, password):
    parameters = {"username": username, "password": password}
    url = server + "/api/user/login"
    resp = requests.post(url, data=parameters, timeout=60)

    if resp.status_code != 200:
        logging.error("login failed, http status code is %i", resp.status_code)
        return None

    resp.encoding = "utf-8"

    return resp.cookies.get_dict()["auth_token"]


def get_documents(server, cookie, limit=0):
    cookies = {"auth_token": cookie}

    url = server + "/api/document/list?limit=" + str(limit)
    resp = requests.get(url, cookies=cookies, timeout=60)

    if resp.status_code != 200:
        logging.error("get_documents failed, http status code is %i",
                      resp.status_code)
        return None

    resp.encoding = "utf-8"

    return json.loads(resp.text)["documents"]


def get_document(server, cookie, document_id):
    cookies = {"auth_token": cookie}
    url = server + "/api/document/" + document_id
    resp = requests.get(url, cookies=cookies, timeout=60)

    if resp.status_code != 200:
        logging.error("get_document failed, http status code is %i",
                      resp.status_code)
        return None

    resp.encoding = "utf-8"

    return json.loads(resp.text)


def update_document(server, cookie, parameter):
    cookies = {"auth_token": cookie}
    url = server + "/api/document/" + parameter["id"]
    resp = requests.post(url, cookies=cookies, data=parameter, timeout=60)

    if resp.status_code != 200:
        logging.error("update_document failed, http status code is %i",
                      resp.status_code)
        logging.error("Code: %i", resp.status_code)
        logging.error("Erro: %s", resp.text)
        return False

    resp.encoding = "utf-8"

    result = json.loads(resp.text)

    if result["id"] != parameter["id"]:
        logging.error(
            "update_document returned wrong document ID. Expected %s, got %s.",
            parameter["id"], result["id"])
        return False

    return True


def add_document(server, cookie, title):
    cookies = {"auth_token": cookie}
    url = server + "/api/document"
    parameters = {"title": title, "language": "deu"}
    resp = requests.put(url, cookies=cookies, data=parameters, timeout=60)

    if resp.status_code != 200:
        logging.error("add_document failed, http status code is %i",
                      resp.status_code)
        return None

    resp.encoding = "utf-8"

    return json.loads(resp.text)["id"]


def delete_document(server, cookie, document_id):
    cookies = {"auth_token": cookie}
    url = server + "/api/document/" + document_id
    resp = requests.delete(url, cookies=cookies, timeout=60)

    if resp.status_code != 200:
        logging.error("delete_document failed, http status code is %i",
                      resp.status_code)
        return False

    result = json.loads(resp.text)

    if result["status"] != "Status OK":
        logging.error("delete_document failed, returned status is %s",
                      result["status"])
        return False

    return True


def add_file(server, cookie, filename, document_id):
    cookies = {"auth_token": cookie}
    url = server + "/api/file"

    # Read content of file
    with open(filename, "rb") as filehandle:
        content = filehandle.read()

    # Strip off path
    purename = os.path.basename(filename)

    # Create dict for requests
    files = {"file": (purename, content)}

    # Set parameters for requests
    parameters = {"id": document_id}
    resp = requests.put(url, cookies=cookies, files=files, data=parameters, timeout=60)

    if resp.status_code != 200:
        logging.error("add_file failed, http status code is %i",
                      resp.status_code)
        return None

    resp.encoding = "utf-8"

    return json.loads(resp.text)


def delete_file(server, cookie, file_id):
    cookies = {"auth_token": cookie}
    url = server + "/api/file/" + file_id

    resp = requests.delete(url, cookies=cookies, timeout=60)

    if resp.status_code != 200:
        logging.error("delete_file failed, http status code is %i",
                      resp.status_code)
        return False

    resp.encoding = "utf-8"

    result = json.loads(resp.text)

    if result["status"] != "Status OK":
        logging.error("delete_file failed, status is %s", result["status"])
        return False

    return True


def get_document_file(server, cookie, document_id):
    cookies = {"auth_token": cookie}
    url = server + "/api/file/list?id=" + document_id
    resp = requests.get(url, cookies=cookies, timeout=60)

    if resp.status_code != 200:
        logging.error("get_document_file failed, http status code is %i",
                      resp.status_code)
        return None

    resp.encoding = "utf-8"

    return json.loads(resp.text)["files"]


def get_file_text(server, cookie, file_id):
    cookies = {"auth_token": cookie}
    url = server + "/api/file/" + file_id + "/data?size=content"
    resp = requests.get(url, cookies=cookies, timeout=60)

    if resp.status_code != 200:
        logging.error("get_file_text failed, http status code is %i",
                      resp.status_code)
        return None

    resp.encoding = "utf-8"

    return resp.text


def get_tags(server, cookie):
    cookies = {"auth_token": cookie}

    url = server + "/api/tag/list"
    resp = requests.get(url, cookies=cookies, timeout=60)

    if resp.status_code != 200:
        logging.error("get_tags failed, http status code is %i",
                      resp.status_code)
        return None

    resp.encoding = "utf-8"

    return json.loads(resp.text)["tags"]


def get_tag(server, cookie, tag_id):
    cookies = {"auth_token": cookie}

    url = server + "/api/tag/" + tag_id
    resp = requests.get(url, cookies=cookies, timeout=60)

    if resp.status_code != 200:
        logging.error("get_tag failed, http status code is %i",
                      resp.status_code)
        return None

    resp.encoding = "utf-8"

    return json.loads(resp.text)


def create_tag(server, cookie, name, color="#3a87ad"):
    cookies = {"auth_token": cookie}
    parameters = {"name": name, "color": color}
    url = server + "/api/tag"
    resp = requests.put(url, cookies=cookies, data=parameters, timeout=60)

    if resp.status_code != 200:
        logging.error("create_tag failed, http status code is %i (%s)",
                      resp.status_code, resp.text)
        return None

    resp.encoding = "utf-8"

    return json.loads(resp.text)["id"]


def create_acl(server, cookie, document_id, target, target_type, permission):
    cookies = {"auth_token": cookie}
    url = server + "/api/acl"
    parameters = {
        "source": document_id,
        "perm": permission,
        "target": target,
        "type": target_type,
    }

    resp = requests.put(url, cookies=cookies, data=parameters, timeout=60)
    if resp.status_code != 200:
        logging.error("create_acl failed, http status code is %i",
                      resp.status_code)
        return None

    resp.encoding = "utf-8"

    return json.loads(resp.text)


def delete_acl(server, cookie, document_id, target, permission):
    cookies = {"auth_token": cookie}
    url = server + "/api/acl_/" + document_id + "/" + permission + "/" + target

    resp = requests.delete(url, cookies=cookies, timeout=60)
    if resp.status_code != 200:
        logging.error("delete_acl failed, http status code is %i",
                      resp.status_code)
        return False

    resp.encoding = "utf-8"

    result = json.loads(resp.text)

    if result["status"] != "Status OK":
        logging.error("delete_acl failed, status is %s", result["status"])
        return False

    return True


def check_acl(acls, target, target_type, permission):
    for acl in acls:
        if acl["name"] == target and acl["perm"] == permission and acl["type"] == target_type:
            return True
    return False


def read_tags(directory):
    files = glob.glob(os.path.join(directory, "*"))

    tags = {}

    for filename in files:
        with open(filename) as filehandle:
            lines = filehandle.readlines()

        lines = [item.strip() for item in lines]

        tagname = os.path.basename(filename)

        tags[tagname] = lines

    return tags


def get_date(text):
    date = None
    next_year = datetime.datetime.now().year + 1

    # This regular expression will try to find dates in the document at
    # hand and will match the following formats:
    # - XX.YY.ZZZZ with XX + YY being 1 or 2 and ZZZZ being 2 or 4 digits
    # - XX/YY/ZZZZ with XX + YY being 1 or 2 and ZZZZ being 2 or 4 digits
    # - XX-YY-ZZZZ with XX + YY being 1 or 2 and ZZZZ being 2 or 4 digits
    # - ZZZZ.XX.YY with XX + YY being 1 or 2 and ZZZZ being 2 or 4 digits
    # - ZZZZ/XX/YY with XX + YY being 1 or 2 and ZZZZ being 2 or 4 digits
    # - ZZZZ-XX-YY with XX + YY being 1 or 2 and ZZZZ being 2 or 4 digits
    # - XX. MONTH ZZZZ with XX being 1 or 2 and ZZZZ being 2 or 4 digits
    # - MONTH ZZZZ, with ZZZZ being 4 digits
    # - MONTH XX, ZZZZ with XX being 1 or 2 and ZZZZ being 4 digits
    date_regex = re.compile(
        r'(\b|(?!=([_-])))([0-9]{1,2})[\.\/-]([0-9]{1,2})[\.\/-]([0-9]{4}|[0-9]{2})(\b|(?=([_-])))|'
        +  # NOQA: E501
        r'(\b|(?!=([_-])))([0-9]{4}|[0-9]{2})[\.\/-]([0-9]{1,2})[\.\/-]([0-9]{1,2})(\b|(?=([_-])))|'
        +  # NOQA: E501
        r'(\b|(?!=([_-])))([0-9]{1,2}[\. ]+[^ ]{3,9} ([0-9]{4}|[0-9]{2}))(\b|(?=([_-])))|'
        +  # NOQA: E501
        r'(\b|(?!=([_-])))([^\W\d_]{3,9} [0-9]{1,2}, ([0-9]{4}))(\b|(?=([_-])))|'
        + r'(\b|(?!=([_-])))([^\W\d_]{3,9} [0-9]{4})(\b|(?=([_-])))')

    # Iterate through all regex matches in text and try to parse the date
    for matches in re.finditer(date_regex, text):
        date_string = matches.group(0)

        try:
            date = dateparser.parse(
                date_string,
                settings={
                    "DATE_ORDER": "DMY",
                    "PREFER_DAY_OF_MONTH": "first",
                    "RETURN_AS_TIMEZONE_AWARE": True
                })
        except (TypeError, ValueError):
            # Skip all matches that do not parse to a proper date
            continue

        if date is not None and next_year > date.year > 1900:
            break

        date = None

    return date


def check_server_tags(server, cookie, tag_names, tag_searches, acl_group):
    for tag in tag_names:
        logging.debug("Checking server Tag %s", tag["name"])
        tag_name = tag["name"]

        logging.debug("Retrieving data for tag %s", tag["name"])
        data = get_tag(server, cookie, tag["id"])

        if not check_acl(data["acls"], acl_group, "GROUP", "READ"):
            logging.info("Adding READ ACL for group %s on tag %s", acl_group,
                         tag["name"])
            create_acl(server, cookie, data["id"], acl_group, "GROUP", "READ")

        if not check_acl(data["acls"], acl_group, "GROUP", "WRITE"):
            logging.info("Adding WRITE ACL for group %s on tag %s", acl_group,
                         tag["name"])
            create_acl(server, cookie, data["id"], acl_group, "GROUP", "WRITE")

        found = False

        for mytag in tag_searches:
            if mytag == tag_name:
                found = True

        if not found:
            logging.error("Please create tag definition for %s", tag["name"])


def check_tag_searches(server, cookie, tag_searches, tag_names, acl_group):
    for tag in tag_searches:
        found = False

        for mytag in tag_names:
            if mytag["name"] == tag:
                found = True
                break

        if found:
            continue

        logging.info("Creating tag %s", tag)
        result_tag = create_tag(server, cookie, tag)
        if result_tag is None:
            logging.error("Failed to create tag %s", tag)

        create_acl(server, cookie, result_tag, acl_group, "GROUP", "READ")
        create_acl(server, cookie, result_tag, acl_group, "GROUP", "WRITE")

        logging.info("Successfully created tag %s with ID %s", tag, result_tag)


def import_file(server, cookie, pathname, acl_group=None):
    purename = os.path.basename(pathname)

    document_result = add_document(server, cookie, purename)
    if document_result is None:
        logging.error("Failed to create document for file %s", purename)
        return None

    logging.debug("Created document %s successfully", document_result)

    file_result = add_file(server, cookie, pathname, document_result)
    if file_result is None:
        logging.error("Failed to add file %s to document %s", purename,
                      document_result)
        delete_document(server, cookie, document_result)
        return None

    logging.debug("Added file %s successfully to document %s",
                  file_result["id"], document_result)

    if acl_group is None:
        return document_result

    acl_result = create_acl(server, cookie, document_result, acl_group,
                            "GROUP", "READ")
    if acl_result is None:
        logging.error("Failed to create READ acl for group %s on document %s",
                      acl_group, document_result)
        delete_file(server, cookie, file_result["id"])
        delete_document(server, cookie, document_result)
        return None

    logging.debug("Successfully created READ acl for group %s on document %s",
                  acl_group, document_result)

    acl_result = create_acl(server, cookie, document_result, acl_group,
                            "GROUP", "WRITE")
    if acl_result is None:
        logging.error("Failed to create WRITE acl for group %s on document %s",
                      acl_group, document_result)
        delete_acl(server, cookie, document_result, "READ", acl_group)
        delete_file(server, cookie, file_result["id"])
        delete_document(server, cookie, document_result)
        return None

    logging.debug("Successfully created WRITE acl for group %s on document %s",
                  acl_group, document_result)

    return document_result


def create_update_data(data):
    update_data = {
        "id": data["id"],
        "title": data["title"],
        "description": data["description"],
        "subject": data["subject"],
        "identifier": data["identifier"],
        "publisher": data["publisher"],
        "format": data["format"],
        "source": data["source"],
        "type": data["type"],
        "coverage": data["coverage"],
        "rights": data["rights"],
        "language": data["language"],
        "create_date": data["create_date"]
    }

    # Pull existing tag into array
    update_data["tags"] = []
    for tag in data["tags"]:
        update_data["tags"].append(tag["id"])

    return update_data


def update_document_tags(server, cookie, document_id, tag_names, tag_searches):
    # Retrieve files for document
    files = get_document_file(server, cookie, document_id)
    if len(files) < 1:
        logging.warning("Document %s has no files, skipping", document_id)
        return False

    logging.info("Document %s has %i files", document_id, len(files))

    # Retrieve document data
    data = get_document(server, cookie, document_id)

    # Create update data
    update_data = create_update_data(data)

    # Retrieve document text
    text = get_file_text(server, cookie, files[0]["id"])
    if text is None or len(text) < 1:
        logging.warning("Document %s has no text, skipping", document_id)
        return False

    update = False

    text_lower = text.lower()
    #text_lower = re.sub(r'[^\w\s]', '', text_lower) # Seems to reduce matching performance, hence disabled

    for tag in tag_names:
        tag_name = tag["name"]

        if not tag_name in tag_searches:
            continue

        found = False

        for search in tag_searches[tag_name]:
            match = search.lower()
            # match = re.sub(r'[^\w\s]', '', match) # Seems to reduce matching performance, hence disabled

            score = fuzz.partial_ratio(match, text_lower)
            if score >= 90:
                found = True

            if text_lower.find(match) != -1:
                found = True

        if not found:
            continue

        if not tag["id"] in update_data["tags"]:
            logging.info("Adding tag %s (%s) to document %s", tag["name"],
                         tag["id"], document_id)
            update_data["tags"].append(tag["id"])
            update = True

    if not update:
        return False

    logging.debug("Updating document %s with %s", document_id,
                  str(update_data))
    if not update_document(server, cookie, update_data):
        logging.error("Updating document %s with %s failed", document_id,
                      str(update_data))

    return True


def update_document_date(server, cookie, document_id):
    # Retrieve files for document
    files = get_document_file(server, cookie, document_id)
    if len(files) < 1:
        logging.warning("Document %s has no files, skipping", document_id)
        return False

    logging.info("Document %s has %i files", document_id, len(files))

    # Retrieve document data
    data = get_document(server, cookie, document_id)

    # Create update data
    update_data = create_update_data(data)

    text = get_file_text(server, cookie, files[0]["id"])
    if text is None or len(text) < 1:
        logging.warning("Document %s has no text, skipping", document_id)
        return False

    date = get_date(text)
    if date is None:
        logging.debug(
            "Unable to extract date from document %s with text length %i",
            document_id, len(text))
        return False

    newdate = int(date.timestamp() * 1000)
    if data["create_date"] == newdate:
        return True

    logging.info("Setting date %s on document %s", date.strftime("%d.%m.%Y"),
                 document_id)
    update_data["create_date"] = newdate

    logging.debug("Updating document %s with %s", document_id,
                  str(update_data))
    if not update_document(server, cookie, update_data):
        logging.error("Updating document %s with %s failed", document_id,
                      str(update_data))
        return False

    return True


def check_document_acls(server, cookie, document_id, acl_group):
    data = get_document(server, cookie, document_id)

    if not check_acl(data["acls"], acl_group, "GROUP", "READ"):
        logging.info("Adding READ ACL for document %s for GROUP %s", acl_group,
                     document_id)
        create_acl(server, cookie, document_id, acl_group, "GROUP", "READ")

    if not check_acl(data["acls"], acl_group, "GROUP", "WRITE"):
        logging.info("Adding WRITE ACL for document %s for GROUP %s",
                     acl_group, document_id)
        create_acl(server, cookie, document_id, acl_group, "GROUP", "WRITE")

    return True


def check_config(config, setting):
    if not config.has_option("DEFAULT", setting):
        logging.error("Please specify %s in the config file", setting)
        sys.exit(1)


def main():
    # Setup command line argument parser
    parser = argparse.ArgumentParser(description="Teedy document annotator")
    parser.add_argument(
        "-c", help="Config file to parse", default="annotator.cfg")
    parser.add_argument(
        "-i", help="Directory to import files from", default="import")
    parser.add_argument("-l", help="Logfile location", default="annotator.log")
    parser.add_argument(
        "-t", help="Directory to read tags from", default="tags")

    # Parse command line arguments
    args = parser.parse_args()

    # Configure logging
    logging.basicConfig(
        format='%(asctime)s %(levelname)s %(message)s',
        datefmt='%d.%m.%Y %H:%M:%S',
        level=logging.DEBUG,
        handlers=[logging.FileHandler(args.l),
                  logging.StreamHandler()])
    logging.getLogger("requests").setLevel(logging.WARNING)
    logging.getLogger("urllib3").setLevel(logging.WARNING)

    last_init = 0
    last_import = 0
    last_tagging = 0

    while True:
        if (time.time() - last_init) > 3600:
            # Read config file
            config = configparser.ConfigParser()
            config.read(args.c)

            # Make sure that we have all the necessary settings present
            check_config(config, "server")
            check_config(config, "username")
            check_config(config, "password")
            check_config(config, "acl_group")

            # Extract required config value
            server = config.get("DEFAULT", "server")
            username = config.get("DEFAULT", "username")
            password = config.get("DEFAULT", "password")
            acl_group = config.get("DEFAULT", "acl_group")

            logging.info("Config file: %s", args.c)
            logging.info("Server: %s", server)
            logging.info("Username: %s", username)
            logging.info("ACL Group: %s", acl_group)
            logging.info("Import Dir: %s", args.i)

            logging.debug("Logging in")
            cookie = login(server, username, password)
            if cookie is None:
                logging.error("Login failed")
                sys.exit(1)
            logging.debug("Login successful, token is %s", cookie)

            logging.debug("Retrieving tag list from server")
            tag_names = get_tags(server, cookie)
            logging.info("%i tags found on the server", len(tag_names))

            logging.debug("Reading tag definitions from file")
            tag_searches = read_tags(args.t)
            logging.info("%i tag definitions found", len(tag_searches))

            # Check if we have definitions for all teedy tags
            logging.debug(
                "Matching server tags and filessystem tag definitions")
            check_server_tags(server, cookie, tag_names, tag_searches,
                              acl_group)

            # Check if we have teedy tags for all tag definitions
            check_tag_searches(server, cookie, tag_searches, tag_names,
                               acl_group)

            last_init = time.time()

        if (time.time() - last_import) > 600:
            # Import files
            logging.debug("Looking for files to import")
            imported = 0
            files = glob.glob(os.path.join(args.i, "*.pdf"))
            for filename in files:
                purename = os.path.basename(filename)

                logging.info("Uploading file %s", purename)

                result = import_file(server, cookie, filename, acl_group)
                if not result:
                    continue

                imported = imported + 1

                logging.info("Successfully uploaded %s as document %s",
                             purename, result)

                # Add the correct tags to the document (if the text is already available)
                update_document_tags(server, cookie, result, tag_names,
                                     tag_searches)

                # Set the proper create_date (if the text is already available)
                update_document_date(server, cookie, result)

                # Delete input file
                os.unlink(filename)
                logging.debug("Successfully deleted file %s", filename)

            if imported > 0:
                logging.info("Imported %i files", imported)

                # Force document tagging right away
                last_tagging = 0

            last_import = time.time()

        if (time.time() - last_tagging) > 86400:
            logging.debug("Retrieving document list")
            documents = get_documents(server, cookie)
            logging.info("%i documents found on the server", len(documents))

            for document in documents:
                logging.debug("Processing %s (%s)", document["title"],
                              document["id"])

                # Update tags for the document
                update_document_tags(server, cookie, document["id"], tag_names,
                                     tag_searches)

                # Ensure correct ACLs for the document
                check_document_acls(server, cookie, document["id"], acl_group)

                # Determine correct create_date for document
                update_document_date(server, cookie, document["id"])

            last_tagging = time.time()

        time.sleep(60)


if __name__ == "__main__":
    main()
