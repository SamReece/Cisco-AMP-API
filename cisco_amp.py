import requests


class CiscoAPI(object):
    """The main suite that contains the JSON ingestion methods"""

    def __init__(self, id, key):
        self.id = id
        self.key = key
        self.version = "https://api.eu.amp.cisco.com/v1/version"

    def __str__(self):
        version = self.connection_without_params(self.version)
        return version

    def connection_session_with_pagination(self, url, payload):
        """establish session without parameters"""
        try:
            session = requests.session()
            output = []
            session.auth = (self.id, self.key)
            response = session.get(url, params=payload)
            response_json = response.json()
            for entity in response_json["data"]:
                output.append(entity)
            while "next" in response_json["metadata"]["links"]:
                next_url = response_json["metadata"]["links"]["next"]
                response = session.get(next_url)
                response_json = response.json()
                for entity in response_json["data"]:
                    output.append(entity)
            return output
        except requests.exceptions.HTTPError as errh:
            return errh
        except requests.exceptions.ConnectionError as errc:
            return errc
        except requests.exceptions.Timeout as errt:
            return errt
        except requests.exceptions.RequestException as err:
            return err

    def connection_with_params(self, url, payload):
        """download with parameters"""
        try:
            request = requests.get(url, auth=(self.id, self.key), params=payload)
            return request
        except requests.exceptions.HTTPError as errh:
            return errh
        except requests.exceptions.ConnectionError as errc:
            return errc
        except requests.exceptions.Timeout as errt:
            return errt
        except requests.exceptions.RequestException as err:
            return err

    def connection_without_params(self, url):
        """download without parameters"""
        try:
            request = requests.get(url, auth=(self.id, self.key))
            return request
        except requests.exceptions.HTTPError as errh:
            return errh
        except requests.exceptions.ConnectionError as errc:
            return errc
        except requests.exceptions.Timeout as errt:
            return errt
        except requests.exceptions.RequestException as err:
            return err


class CiscoAPIUsers(CiscoAPI):
    """
    Fetch list of computers that have observed activity by given user name
    """

    def __init__(self, id, key, limit=500, offset=0):
        super().__init__(id, key)
        self.url = "https://api.eu.amp.cisco.com/v1/computers/user_activity"
        self.limit = limit
        self.offset = offset

    def user_activity(self, user):
        payload = {"q": user, "limit": self.limit, "offset": self.offset}
        user = self.connection_with_params(self.url, payload)
        return user.json()


class CiscoAPIComputers(CiscoAPI):
    """
    This endpoint provides you with the ability to
    search all computers across your organization
    for any events or activities associated with a
    file or network operation, and returns computers
    matching that criteria.

    The 'hostname' and 'q' search is conducted with an ending
    wildcard so a list of hosts will be returned if
    multiple matches occur.
    """

    def __init__(self, id, key, limit=500, offset=0):
        super().__init__(id, key)
        self.limit = limit
        self.offset = offset
        self.url = "https://api.eu.amp.cisco.com/v1/computers"
        self.urlActivity = "https://api.eu.amp.cisco.com/v1/computers/activity"

    def computer_list(self):
        computers = self.connection_without_params(self.url)
        return computers.json()

    def computer_list_filtered_by_name(self, name):
        payload = {"hostname": name, "limit": self.limit, "offset": self.offset}
        computers = self.connection_with_params(self.url, payload)
        return computers.json()

    def computer_list_filtered_by_group_guid(self, guid):
        payload = {"group_guid": guid, "limit": self.limit, "offset": self.offset}
        guidComputers = self.connection_session_with_pagination(self.url, payload)
        return guidComputers

    def computers_by_internal_ip(self, ipaddress):
        payload = {"internal_ip": ipaddress, "limit": self.limit, "offset": self.offset}
        computersByIP = self.connection_with_params(self.url, payload)
        return computersByIP.json()

    def computers_by_external_ip(self, ipaddress):
        payload = {"external_ip": ipaddress, "limit": self.limit, "offset": self.offset}
        computersByIP = self.connection_with_params(self.url, payload)
        return computersByIP.json()

    def file_activity(self, fileName):
        payload = {"q": fileName, "offset": self.offset, "limit": self.limit}
        fileActivity = self.connection_with_params(self.url, payload)
        return fileActivity.json()

    def url_activity(self, urlName):
        payload = {"q": urlName, "offset": self.offset, "limit": self.limit}
        activity = self.connection_with_params(self.urlActivity, payload)
        return activity.json()

    def sha256_activity(self, sha256):
        payload = {"q": sha256, "offset": self.offset, "limit": self.limit}
        activity = self.connection_with_params(self.urlActivity, payload)
        return activity.json()

    def internet_protocol_activity(self, ipaddress):
        payload = {"q": ipaddress, "offset": self.offset, "limit": self.limit}
        ipActivity = self.connection_with_params(self.urlActivity, payload)
        return ipActivity.json()


class CiscoAPIGroups(CiscoAPI):
    """
    Provides basic information about groups in your
    organization. This endpoint is provided so that
    you can map group names to guids for filtering
    on the events endpoint.
    """

    def __init__(self, id, key, limit=5):
        super().__init__(id, key)
        self.url = "https://api.eu.amp.cisco.com/v1/groups"
        self.limit = limit

    def groups(self):
        groups = self.connection_without_params(self.url)
        return groups.json()

    def group_list_filtered_by_name(self, name):
        payload = {"name": name, "limit": 500}
        groups = self.connection_with_params(self.url, payload)
        return groups.json()


class CiscoAPIEvents(CiscoAPI):
    """
    This is a general query interface for events.
    This is analogous to the Events view on the FireAMP Console.

    Events can be filtered by a variety of criteria. Each criteria
    type is logically ANDed with the other criteria; each
    selection of a criteria is logically ORed.

    The arguments passed to the event_type and group_guid parameters
    can be retrieved from their respective endpoints.
    """

    def __init__(self, id, key, limit=500, offset=0):
        super().__init__(id, key)
        self.url = "https://api.eu.amp.cisco.com/v1/events"
        self.limit = limit
        self.offset = offset

    def events_filtered_by_detection_sha_detection(self, sha):
        payload = {"detection_sha256": sha, "limit": self.limit}
        sha = self.connection_with_params(self.url, payload)
        return sha.json()

    def events_filtered_by_application_sha_detection(self, sha):
        payload = {"application_sha256": sha, "limit": self.limit}
        sha = self.connection_with_params(self.url, payload)
        return sha.json()

    def events_sorted_in_descending_order_by_timestamp(self):
        payload = {"limit": self.limit}
        OrderedByTime = self.connection_with_params(self.url, payload)
        return OrderedByTime.json()

    def events_filtered_by_connector_guid(self, guid):
        payload = {"connector_guid": guid, "limit": self.limit}
        connectorGuid = self.connection_with_params(self.url, payload)
        return connectorGuid.json()

    def events_filtered_by_group_guid(self, guid):
        payload = {"group_guid": guid, "limit": self.limit}
        groupGuid = self.connection_with_params(self.url, payload)
        return groupGuid.json()

    def events_filtered_by_event_type(self, event):
        payload = {"event_type": event, "limit": self.limit}
        eventType = self.connection_with_params(self.url, payload)
        return eventType.json()

    def fetch_events_newer_than_timestamp(self, start):
        payload = {"start_date": start, "offset": self.offset, "limit": self.limit}
        eventsSinceTimeStamp = self.connection_with_params(self.url, payload)
        return eventsSinceTimeStamp.json()

    def fetch_list_of_behavioral_protection_events(self, event):
        payload = {"event_type": event, "limit": self.limit}
        behaviour = self.connection_with_params(self.url, payload)
        return behaviour.json()


class CiscoAPIPolicies(CiscoAPI):
    """
    Returns a list of policies. You can filter this list
    by name and product.
    """

    def __init__(self, id, key, limit=500, offset=0):
        super().__init__(id, key)
        self.url = "https://api.eu.amp.cisco.com/v1/policies"
        self.limit = limit
        self.offset = offset

    def policies(self):
        payload = {"limit": self.limit, "offset": self.offset}
        policies = self.connection_with_params(self.url, payload)
        return policies.json()

    def policy_by_name(self, name):
        payload = {"name": name, "limit": self.limit, "offset": self.offset}
        policyName = self.connection_with_params(self.url, payload)
        return policyName.json()

    def policy_by_product(self, product):
        payload = {"product": product, "limit": self.limit, "offset": self.offset}
        policyProduct = self.connection_with_params(self.url, payload)
        return policyProduct.json()


class CiscoAPIVulnerabilities(CiscoAPI):
    """
    This is a general query interface for vulnerabilities.
    This is analogous to the Vulnerable Software view on
    the AMP for Endpoints Console.

    The list can be filtered to show only the vulnerable
    programs detected for a specific time range.

    For example: with the query string:
    start_time=2021-05-15&end_time=2021-05-20,

    it will return any vulnerable applications
    observed during the period 2021-05-15 - 2021-05-20.

    start_time, end_time params accepts date and time expressed according to ISO 8601.
    """

    def __init__(self, id, key, limit=500, offset=0):
        super().__init__(id, key)
        self.url = "https://api.eu.amp.cisco.com/v1/vulnerabilities"
        self.limit = limit
        self.offset = offset

    def vulnerabilities_list(self):
        payload = {"offset": self.offset, "limit": self.limit}
        vulnerabilities = self.connection_with_params(self.url, payload)
        return vulnerabilities.json()

    def vulnerabilities_by_group_guid(self, guid):
        payload = {"group_guid": guid, "offset": self.offset, "limit": self.limit}
        vulnerabilitiesByGUID = self.connection_with_params(self.url, payload)
        return vulnerabilitiesByGUID.json()

    def vulnerabilities_filtered_by_time_range(self, start, end):
        payload = {
            "start_time": start,
            "end_time": end,
            "offset": self.offset,
            "limit": self.limit,
        }
        vulnerabilitiesByTimeRange = self.connection_with_params(self.url, payload)
        return vulnerabilitiesByTimeRange.json()

    def vulnerabilities_filtered_by_date_range(self, start, end):
        payload = {
            "start_time": start,
            "end_time": end,
            "offset": self.offset,
            "limit": self.limit,
        }
        vulnerabilitiesByDateRange = self.connection_with_params(self.url, payload)
        return vulnerabilitiesByDateRange.json()