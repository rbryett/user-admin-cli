import pytest

from rbac import *


def clear_csv():
    for file in [USERS_CSV, POLICIES_CSV, DATA_CLASSIFICATION_CSV]:
        with open(file, 'r+') as f:
            lines = f.readlines()
            f.seek(0)
            f.truncate()
            f.writelines(lines[0])


@pytest.fixture(autouse=True)
def cleanup():
    clear_csv()
    yield
    clear_csv()


class Namespace(object):
    """
    Replicates the Namespace object we'd receive from argparse.
    """
    def __init__(
            self,
            resource_type=None,
            action=None,
            username=None,
            groups=None,
            name=None,
            database=None,
            table=None,
            pii=None
    ):
        self.resource_type = resource_type
        self.action = action
        self.username = username
        self.name = name
        self.groups = groups
        self.database = database
        self.table = table
        self.pii = pii


def test_resource_type_user():
    r = Resource(Namespace(resource_type="user", action="create", username="test_user"))
    assert isinstance(r.resource, User)


def test_resource_type_user_no_username():
    with pytest.raises(ValueError):
        Resource(Namespace(resource_type="user", action="create"))


def test_resource_type_policy():
    r = Resource(Namespace(resource_type="policy", action="create", name="test_policy"))
    assert isinstance(r.resource, Policy)


def test_resource_type_policy_no_policy():
    with pytest.raises(ValueError):
        Resource(Namespace(resource_type="policy", action="create"))


def test_resource_type_data_classification():
    r = Resource(Namespace(resource_type="dc", action="create", database="test_db"))
    assert isinstance(r.resource, DataClassification)


def test_resource_type_data_classification_no_database():
    with pytest.raises(ValueError):
        Resource(Namespace(resource_type="dc", action="create", table="test_table"))


def test_resource_type_no_type():
    with pytest.raises(TypeError):
        Resource(Namespace())


def test_user_create():
    num_of_users = len(Users())
    Users().add_user(User(username="test_user", groups=["test", "group"]))
    assert len(Users()) == num_of_users + 1


def test_resource_user_implement():
    num_of_users = len(Users())
    Resource(
        Namespace(resource_type="user", action="create", username="test_user", groups=["test", "group"])
    ).implement()
    assert len(Users()) == num_of_users + 1


def test_user_get_user():
    Users().add_user(User(username="test_user", groups=["test", "group"]))
    user = User.get_user("test_user")
    assert user.name == "test_user" and [ag == eg for ag, eg in zip(user.groups, ["group", "test"])]


def test_user_remove():
    Users().add_user(User(username="test_user", groups=["test", "group"]))
    num_of_users = 1
    assert len(Users()) == num_of_users
    u = User(username="test_user")
    u.remove()
    num_of_users -= 1
    assert len(Policies()) == num_of_users


def test_policy_create():
    num_of_policies = len(Policies())
    Policies().add_policy(Policy(policy_name="test_policy", groups=["test", "group"]))
    num_of_policies += 1
    assert len(Policies()) == num_of_policies


def test_resource_policy_implement():
    num_of_policies = len(Policies())
    Resource(
        Namespace(resource_type="policy", action="create", name="test_user", groups=["test", "group"])
    ).implement()
    num_of_policies += 1
    assert len(Policies()) == num_of_policies


def test_policy_get_policy():
    Policies().add_policy(Policy(policy_name="test_policy", groups=["test", "group"]))
    policy = Policy.get_policy("test_policy")
    assert policy.name == "test_policy" and [ag == eg for ag, eg in zip(policy.groups, ["group", "test"])]


def test_policy_remove():
    Policies().add_policy(Policy(policy_name="test_policy", groups=["test", "group"]))
    num_of_policies = 1
    assert len(Policies()) == num_of_policies
    p = Policy(policy_name="test_policy")
    p.remove()
    num_of_policies -= 1
    assert len(Policies()) == num_of_policies


def test_data_classification_create():
    num_of_dcs = len(DataClassifications())
    DataClassifications().add_data_classification(
        DataClassification(database_name="test_database", table_name="test_ttable", pii="true"))
    num_of_dcs += 1
    assert len(DataClassifications()) == num_of_dcs


def test_data_classification_implement():
    num_of_dcs = len(DataClassifications())
    Resource(
        Namespace(resource_type="dc", action="create", database="test_database", table="test_table", pii="true")
    ).implement()
    num_of_dcs += 1
    assert len(DataClassifications()) == num_of_dcs


def test_data_classification_get_dc():
    DataClassifications().add_data_classification(
        DataClassification(database_name="test_database", table_name="test_table", pii="true"))
    dc = DataClassification.get_dc("test_database", "test_table")
    assert dc.database_name == "test_database" and dc.table_name == "test_table" and dc.pii == "true"


def test_data_classification_remove():
    DataClassifications().add_data_classification(
        DataClassification(database_name="test_database", table_name="test_ttable", pii="true"))
    num_of_dcs = 1
    assert len(DataClassifications()) == num_of_dcs
    dc = DataClassification(database_name="test_database")
    dc.remove()
    num_of_dcs -= 1
    assert len(DataClassifications()) == num_of_dcs



#TODO: Test Custom Exceptions raised correctly
#TODO: Test new headers are created
#TODO: Test serialisation
#TODO: Test Policy, User and DataClassification objects are correctly populated after CSV read
#TODO: Test List