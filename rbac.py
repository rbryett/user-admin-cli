import argparse
import csv
import os

USERS_CSV = os.environ.get("USERS_CSV") or "test/testdata/users-management.csv"
POLICIES_CSV = os.environ.get("POLICIES_CSV") or "test/testdata/roles-test.csv"
DATA_CLASSIFICATION_CSV = os.environ.get("DATA_CLASSIFICATION_CSV") or "test/testdata/data-classification.csv"


class NoGroupFound(Exception):
    def __init__(self, group_name):
        self.group_name = group_name


class NoUserFound(Exception):
    def __init__(self, username):
        self.username = username


class NoPolicyFound(Exception):
    def __init__(self, policy_name):
        self.policy_name = policy_name


class NoDatabaseFound(Exception):
    def __init__(self, database_name):
        self.database_name = database_name


class Resource(object):
    def __init__(self, resource):
        self.action = resource.action
        self.type = resource.resource_type

        if resource.action != "list":
            if resource.resource_type == "user":
                self.resource = User(resource.username, resource.groups)
            elif resource.resource_type == "policy":
                self.resource = Policy(resource.name, resource.groups)
            elif resource.resource_type == "dc":
                self.resource = DataClassification(resource.database, resource.table, resource.pii)
            else:
                raise TypeError("unknown resource type: {}".format(resource.resource_type))

    def implement(self):
        if self.action == "list":
            self.list_resources()
        else:
            getattr(self.resource, self.action)()

    def list_resources(self):
        if self.type == "user":
            print(repr(Users()))
        elif self.type == "policy":
            print(repr(Policies()))
        elif self.type == "dc":
            print(repr(DataClassifications()))
        else:
            raise TypeError("type '{}' not supported".format(self.type))


class Users(object):
    def __init__(self):
        with open(USERS_CSV) as csv_file:
            csv_reader = csv.DictReader(csv_file)
            raw_userdata = [i for i in csv_reader]
            self.headers = csv_reader.fieldnames
            self.users = self.process_userdata(raw_userdata)

    def __getitem__(self, username):
        for user in self.users:
            if user.name == username:
                return user

    def __iter__(self):
        return iter(self.users)

    def __len__(self):
        return len(self.users)

    def __repr__(self):
        lines = list()
        lines.append("| {:^50} | {:^100} |".format("-" * 50, "-" * 100))
        lines.append("| {:^50} | {:^100} |".format("Usernames", "Groups"))
        lines.append("| {:^50} | {:^100} |".format("-" * 50, "-" * 100))
        for u in self.users:
            lines.append("| {:^50} | {:^100} |".format("-" * 50, "-" * 100))
            lines.append("| {:<50} | {:<100} |".format(u.name, ""))
            for g in u.groups:
                lines.append("| {:<50} | {:<100} |".format("", g))
        lines.append("| {:^50} | {:^100} |".format("-" * 50, "-" * 100))
        return "\n".join(lines)

    @staticmethod
    def process_userdata(raw_userdata):
        users = []
        for user in raw_userdata:
            username = user["user"]
            user_groups = []
            for i in user:
                if user[i] == "1":
                    user_groups.append(i)
            users.append(User(username, user_groups))
        return users

    def add_user(self, user):
        if isinstance(user, User):
            self.users.append(user)

            # Retry logic for adding new headers
            while isinstance(user.serialise_csv(self.headers), NoGroupFound):
                self.headers.append(user.serialise_csv(self.headers).group_name)
            serialised_entry = user.serialise_csv(self.headers)

            # Read existing csv file and store as list of dicts
            csv_entries = list()
            with open(USERS_CSV, 'r') as csv_file:
                reader = csv.DictReader(csv_file)
                for entry in reader:
                    # if user already exists, don't append it
                    if entry["user"] == user.name:
                        continue
                    csv_entries.append(entry)

            # Append new entry to existing items
            csv_entries.append(serialised_entry)

            # Write all entries, include new entry back to CSV with additional headers if applicable
            with open(USERS_CSV, 'w') as csv_file:
                writer = csv.DictWriter(csv_file, self.headers, lineterminator="\n")
                writer.writeheader()
                writer.writerows(csv_entries)

        else:
            print("cannot add type '{}' to users".format(type(user)))

    def remove_user(self, user):
        if isinstance(user, User):
            for u in self.users:
                if user.name == u.name:
                    self.users.remove(u)

            amended_entries = list()
            with open(USERS_CSV, 'r') as csv_file:
                for entry in csv.reader(csv_file):
                    amended_entries.append(entry)
                    if entry[0] == user.name:
                        amended_entries.remove(entry)
                        print("removed user '{}' from entries".format(user.name))

            with open(USERS_CSV, 'w') as csv_file:
                writer = csv.writer(csv_file)
                writer.writerows(amended_entries)


class User(object):
    def __init__(self, username, groups=[]):
        if username is None:
            raise ValueError("no username provided")
        self.name = username
        self.groups = groups

    def serialise_csv(self, headers):
        serialised_data = {headers[0]: self.name}
        for g in self.groups:
            if g not in headers[1:]:
                return NoGroupFound(g)

        for h in headers[1:]:
            if h in self.groups:
                serialised_data[h] = "1"
            else:
                serialised_data[h] = ""
        return serialised_data

    def create(self):
        try:
            self.get_user(self.name)
            print("user '{}' exists - overwriting entry with new values".format(self.name))
            Users().add_user(self)
        except NoUserFound:
            Users().add_user(self)
            print("created user '{}'".format(self.name))
        except Exception as e:
            print("Unexpected Error: {}".format(e))

    def remove(self):
        Users().remove_user(self)

    def get(self):
        try:
            user = self.get_user(self.name)
            self.groups = user.groups
            print(
                """username: {}
groups: {}""".format(self.name, self.groups)
            )
        except NoUserFound as e:
            print("cannot find user with name '{}'".format(e.username))

    @staticmethod
    def get_user(username):
        user = Users()[username]
        if user is not None:
            return user
        else:
            raise NoUserFound(username)


class Policies(object):
    def __init__(self):
        with open(POLICIES_CSV) as csv_file:
            csv_reader = csv.DictReader(csv_file)
            raw_policy_data = [i for i in csv_reader]
            self.headers = csv_reader.fieldnames
            self.policies = self.process_policy_data(raw_policy_data)

    def __getitem__(self, policy_name):
        for policy in self.policies:
            if policy.name == policy_name:
                return policy

    def __iter__(self):
        return iter(self.policies)

    def __len__(self):
        return len(self.policies)

    def __repr__(self):
        lines = list()
        lines.append("| {:^50} | {:^100} |".format("-" * 50, "-" * 100))
        lines.append("| {:^50} | {:^100} |".format("Policy Names", "Groups"))
        lines.append("| {:^50} | {:^100} |".format("-" * 50, "-" * 100))
        for p in self.policies:
            lines.append("| {:^50} | {:^100} |".format("-" * 50, "-" * 100))
            lines.append("| {:<50} | {:<100} |".format(p.name, ""))
            for g in p.groups:
                lines.append("| {:<50} | {:<100} |".format("", g))
        lines.append("| {:^50} | {:^100} |".format("-" * 50, "-" * 100))
        return "\n".join(lines)

    @staticmethod
    def process_policy_data(raw_policy_data):
        policies = []
        for policy in raw_policy_data:
            policy_name = policy["policy"]
            policy_groups = []
            for i in policy:
                if policy[i] == "1":
                    policy_groups.append(i)
            policies.append(Policy(policy_name, policy_groups))
        return policies

    def add_policy(self, policy):
        if isinstance(policy, Policy):
            self.policies.append(policy)

            # Retry logic for adding new headers
            while isinstance(policy.serialise_csv(self.headers), NoGroupFound):
                self.headers.append(policy.serialise_csv(self.headers).group_name)
            serialised_entry = policy.serialise_csv(self.headers)

            # Read existing csv file and store as list of dicts
            csv_entries = list()
            with open(POLICIES_CSV, 'r') as csv_file:
                reader = csv.DictReader(csv_file)
                for entry in reader:
                    # if user already exists, don't append it
                    if entry["policy"] == policy.name:
                        continue
                    csv_entries.append(entry)

            # Append new entry to existing items
            csv_entries.append(serialised_entry)

            # Write all entries, include new entry back to CSV with additional headers if applicable
            with open(POLICIES_CSV, 'w') as csv_file:
                writer = csv.DictWriter(csv_file, self.headers, lineterminator="\n")
                writer.writeheader()
                writer.writerows(csv_entries)

        else:
            print("cannot add type '{}' to policies".format(type(policy)))

    def remove_policy(self, policy):
        if isinstance(policy, Policy):
            for p in self.policies:
                if policy.name == p.name:
                    self.policies.remove(p)

            amended_entries = list()
            with open(POLICIES_CSV, 'r') as csv_file:
                for entry in csv.reader(csv_file):
                    amended_entries.append(entry)
                    if entry[0] == policy.name:
                        amended_entries.remove(entry)
                        print("removed policy '{}' from entries".format(policy.name))

            with open(POLICIES_CSV, 'w') as csv_file:
                writer = csv.writer(csv_file)
                writer.writerows(amended_entries)


class Policy(object):
    def __init__(self, policy_name, groups):
        if policy_name is None:
            raise ValueError("no policy name provided")
        self.name = policy_name
        self.groups = groups

    def serialise_csv(self, headers):
        serialised_data = {headers[0]: self.name}
        for g in self.groups:
            if g not in headers[1:]:
                return NoGroupFound(g)

        for h in headers[1:]:
            if h in self.groups:
                serialised_data[h] = "1"
            else:
                serialised_data[h] = ""
        return serialised_data

    def create(self):
        try:
            self.get_policy(self.name)
            print("policy '{}' exists - overwriting entry with new values".format(self.name))
            Policies().add_policy(self)
        except NoPolicyFound:
            Policies().add_policy(self)
            print("created policy '{}'".format(self.name))
        except Exception as e:
            print("Unexpected Error: {}".format(e))

    def remove(self):
        Policies().remove_policy(self)

    def get(self):
        try:
            policy = self.get_policy(self.name)
            self.groups = policy.groups
            print(
                """Policy: {}
groups: {}""".format(self.name, self.groups)
            )
        except NoPolicyFound as e:
            print("cannot find policy with name '{}'".format(e.policy_name))

    @staticmethod
    def get_policy(policy_name):
        policy = Policies()[policy_name]
        if policy is not None:
            return policy
        else:
            raise NoPolicyFound(policy_name)


class DataClassifications(object):
    def __init__(self):
        with open(DATA_CLASSIFICATION_CSV) as csv_file:
            csv_reader = csv.DictReader(csv_file)
            raw_dc_data = [i for i in csv_reader]
            self.headers = csv_reader.fieldnames
            self.data_classifications = self.process_data_classification_data(raw_dc_data)

    def __getitem__(self, database_name, table_name=None):
        dcs = list()
        for dc in self.data_classifications:
            if dc.database_name == database_name:
                if table_name is not None:
                    if dc.table_name == table_name:
                        return dc
                else:
                    dcs.append(dc)
        return dcs

    def __iter__(self):
        return iter(self.data_classifications)

    def __len__(self):
        return len(self.data_classifications)

    def __repr__(self):
        lines = list()
        lines.append("| {:^30} | {:^30} | {:^30} |".format("-" * 30, "-" * 30, "-" * 30))
        lines.append("| {:^30} | {:^30} | {:^30} |".format("Database", "Table", "PII"))
        lines.append("| {:^30} | {:^30} | {:^30} |".format("-" * 30, "-" * 30, "-" * 30))
        for dc in self.data_classifications:
            lines.append("| {:^30} | {:^30} | {:^30} |".format(dc.database_name, dc.table_name, dc.pii))
        lines.append("| {:^30} | {:^30} | {:^30} |".format("-" * 30, "-" * 30, "-" * 30))
        return "\n".join(lines)

    @staticmethod
    def process_data_classification_data(raw_dc_data):
        dcs = []
        for dc in raw_dc_data:
            database_name = dc["db"]
            table_name = dc["table"]
            pii = dc["pii"]
            dcs.append(DataClassification(database_name, table_name, pii))
        return dcs

    def add_data_classification(self, data_classification):
        if isinstance(data_classification, DataClassification):
            self.data_classifications.append(data_classification)

            serialised_entry = data_classification.serialise_csv(self.headers)

            # Read existing csv file and store as list of dicts
            csv_entries = list()
            with open(DATA_CLASSIFICATION_CSV, 'r') as csv_file:
                reader = csv.DictReader(csv_file)
                for entry in reader:
                    # if data classification already exists, don't append it
                    if entry["db"] == data_classification.database_name and \
                            entry["table"] == data_classification.table_name:
                        continue
                    csv_entries.append(entry)

            # Append new entry to existing items
            csv_entries.append(serialised_entry)

            # Write all entries, include new entry back to CSV with additional headers if applicable
            with open(DATA_CLASSIFICATION_CSV, 'w') as csv_file:
                writer = csv.DictWriter(csv_file, self.headers, lineterminator="\n")
                writer.writeheader()
                writer.writerows(csv_entries)

        else:
            print("cannot add type '{}' to data classifications".format(type(data_classification)))

    def remove_data_classification(self, data_classification):
        if isinstance(data_classification, DataClassification):
            for dc in self.data_classifications:
                if data_classification.database_name == dc.database_name and \
                        data_classification.table_name == dc.table_name:
                    self.data_classifications.remove(dc)

            amended_entries = list()
            removed_entry = False
            with open(DATA_CLASSIFICATION_CSV, 'r') as csv_file:
                for entry in csv.reader(csv_file):
                    amended_entries.append(entry)
                    if entry[0] == data_classification.database_name and \
                            entry[1] == data_classification.table_name:
                        amended_entries.remove(entry)
                        removed_entry = True
                        print("removed data classification '{}:{}:{}' from entries"
                              .format(data_classification.database_name,
                                      data_classification.table_name,
                                      data_classification.pii))

            if not removed_entry:
                print("unable to remove data classification starting with '{}:{}'"
                      .format(data_classification.database_name,
                              data_classification.table_name))

            with open(DATA_CLASSIFICATION_CSV, 'w') as csv_file:
                writer = csv.writer(csv_file)
                writer.writerows(amended_entries)


class DataClassification(object):
    def __init__(self, database_name, table_name, pii):
        if database_name is None:
            raise ValueError("no policy name provided")
        self.database_name = database_name
        self.table_name = table_name
        self.pii = pii

    def serialise_csv(self, headers):
        serialised_data = {
            headers[0]: self.database_name,
            headers[1]: self.table_name,
            headers[2]: self.pii
        }
        return serialised_data

    def create(self):
        try:
            self.get_dc(self.database_name, self.table_name)
            print("data classification '{}:{}:{}' exists - overwriting entry with new values"
                  .format(self.database_name, self.table_name, self.pii))
            DataClassifications().add_data_classification(self)
        except NoDatabaseFound:
            DataClassifications().add_data_classification(self)
            print("created data classification '{}:{}:{}'"
                  .format(self.database_name, self.table_name, self.pii))
        except Exception as e:
            print("Unexpected Error: {}".format(e))

    def remove(self):
        try:
            dc = self.get_dc(self.database_name, self.table_name)
            if isinstance(dc, list):
                for i in dc:
                    DataClassifications().remove_data_classification(i)
            else:
                DataClassifications().remove_data_classification(dc)
        except NoDatabaseFound as e:
            print("cannot remove Data Classification with Database named '{}'".format(e.database_name))

    def get(self):
        try:
            data_classification = self.get_dc(self.database_name, self.table_name)
            if isinstance(data_classification, list):
                for dc in data_classification:
                    print(
                        """
===========================
Database: {}
Table: {}
PII: {}
===========================""".format(dc.database_name, dc.table_name, dc.pii)
                    )
            else:
                self.table_name = data_classification.table_name
                self.pii = data_classification.pii
                print(
                    """Database: {}
Table: {}
PII: {}""".format(self.database_name, self.table_name, self.pii)
                )
        except NoDatabaseFound as e:
            print("cannot find Data Classification with Database named '{}'".format(e.database_name))

    # TODO: Raise NoTableFound if its the table that is missing
    @staticmethod
    def get_dc(database_name, table_name):
        dc = DataClassifications().__getitem__(database_name, table_name)
        if dc is not None:
            return dc
        else:
            raise NoDatabaseFound(database_name)


def retrieve_args():
    parser = argparse.ArgumentParser(description="Manage users in DWX RBAC2.0")
    sub_parsers = parser.add_subparsers(help="sub-command help", dest="action")

    create = sub_parsers.add_parser("create", help="create a resource")
    remove = sub_parsers.add_parser("remove", help="remove a resource")
    _list = sub_parsers.add_parser("list", help="list a resource")
    get = sub_parsers.add_parser("get", help="get a resource")

    for action in [create, remove, _list, get]:
        sp = action.add_subparsers(help="manage a type of resource", dest="resource_type")
        user = sp.add_parser("user", help="manage a user resource")
        policy = sp.add_parser("policy", help="manage a policy resource")
        data_classification = sp.add_parser("dc", help="manage a data classification resource")

        required_arg = False
        if action == _list:
            continue
        elif action == create:
            required_arg = True
        init_arguments(user, policy, data_classification, required_arg)

    return parser


def init_arguments(user, policy, data_classification, required):
    user.add_argument("--username", required=True)
    user.add_argument("--groups", nargs="+", required=required)

    policy.add_argument("--name", required=True)
    policy.add_argument("--groups", nargs="+", required=required)

    data_classification.add_argument("--database", required=True)
    data_classification.add_argument("--table", required=required)
    data_classification.add_argument("--pii", choices=["true", "false"], required=required)


def main(args):
    Resource(args).implement()


if __name__ == '__main__':
    main(retrieve_args().parse_args())
