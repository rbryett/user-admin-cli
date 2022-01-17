#RBAC Admin CLI
This is a tool used to easily visualise and configure existing and 
new users, policies and data classifications as part of the RBAC 
2.0 workflow.

###Commit
Since the configuration files that are being edited need commiting to
git, there is a `--commit` flag that can be issued standalone 
(e.g. `rbac --commit`) or alongside commands that alter the state of RBAC
(e.g. `rbac username="someuser" add-groups="group1,group2" --commit`).

Note this doesn't apply in some cases, when listing a users groups 
for example.

###Add a user
`rbac user create username="someuser" groups="group1,group2"`
`rbac user create username="someuser" --commit`

###Remove a user
`rbac user remove username="someuser"`
`rbac user remove username="someuser" --commit`

###List a users groups
`rbac user list`

###Retrieve user attributes
`rbac user get username="someuser"`

###Add a Policy
`rbac policy create policy="somepolicy" groups="group1,group2"`
`rbac policy create policy="somepolicy" groups="group1,group2" --commit`

###Remove a Policy
`rbac policy remove policy="somepolicy"`
`rbac policy remove policy="somepolicy" --commit`

###List policies
`rbac policy list`

###Retrieve policy attributes
`rbac policy get policy="somepolicy"`

###Add a Data Classification
`rbac dc create database="somedb" table="sometable" pii=true`
`rbac dc create database="somedb" table="sometable" pii=false --commit`

###Remove a Data Classification
`rbac dc remove database="somedb"`
`rbac dc remove database="somedb" table="sometable" --commit`

###List Data Classification
`rbac dc list`

###Retrieve Data Classification attributes
`rbac dc get database="somedb"`
