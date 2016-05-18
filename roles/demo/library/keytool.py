#!/usr/bin/python
import os

def test_keytool(module):
    ''' Test if keytool is present '''
    test_cmd = "/opt/java/current/bin/keytool"

    (rc, del_out, del_err) = module.run_command(test_cmd, check_rc=True)

def test_keystore(module, keystore_path):
    ''' Check if we can access keystore as file or not '''
    # if keystore_path is None:
    #      keystore_path=''
    if not os.path.exists(keystore_path) or not os.path.isfile(keystore_path):
        ## Keystore doesn't exist we want to create it
        return module.fail_json(changed=False, msg="Module require existing keystore at keystore_path '%s'" % keystore_path)

def check_cert_present(module, keystore_path, keystore_pass, alias):
    test_cmd = "/opt/java/current/bin/keytool -noprompt -list -keystore '%s' -storepass '%s' -alias '%s'" % (keystore_path, keystore_pass, alias)

    (rc, out, err) = module.run_command(test_cmd)
    if rc == 0:
        return True
    return False

def import_cert_url(module, url, port, keystore_path, keystore_pass, alias):
    fetch_cmd = "/opt/java/current/bin/keytool -printcert -rfc -sslserver %s:%s" % (url, port)
    import_cmd = "/opt/java/current/bin/keytool -importcert -noprompt -keystore '%s' -storepass '%s' -alias '%s'" % (keystore_path, keystore_pass, alias)

    # Fetch SSL certificate from remote host.
    (rc, fetch_out, fetch_err) = module.run_command(fetch_cmd, check_rc=True)

    # Use remote certificate from remote host and import it to a java keystore
    (rc, import_out, import_err) = module.run_command(import_cmd, data=fetch_out, check_rc=False)
    if rc == 0:
        return module.exit_json(changed=True, msg=import_out,
            rc=rc, cmd=import_cmd, stdout_lines=import_out)
    else:
        return module.fail_json(msg=import_out, rc=rc, cmd=import_cmd)


def import_cert_path(module, path, keystore_path, keystore_pass, alias):
    import_cmd = "/opt/java/current/bin/keytool -importcert -noprompt -keystore '%s' -storepass '%s' -file '%s' -alias '%s'" % (keystore_path, keystore_pass, path, alias)

    # Use local certificate from local path and import it to a java keystore
    (rc, import_out, import_err) = module.run_command(import_cmd, check_rc=False)
    if rc == 0:
        return module.exit_json(changed=True, msg=import_out,
            rc=rc, cmd=import_cmd, stdout_lines=import_out)
    else:
        return module.fail_json(msg=import_out, rc=rc, cmd=import_cmd)


def delete_cert(module, keystore_path, keystore_pass, alias):
    del_cmd = "/opt/java/current/bin/keytool -delete -keystore '%s' -storepass '%s' -alias '%s'" % (keystore_path, keystore_pass, alias)

    # Delete SSL certificate from keystore
    (rc, del_out, del_err) = module.run_command(del_cmd, check_rc=True)

    return module.exit_json(changed=True, msg=del_out,
        rc=rc, cmd=del_cmd, stdout_lines=del_out)

def main():
    argument_spec = dict(
        alias = dict(required=False),
        keystore_location = dict(required=False, default='/opt/java/current/jre/lib/security/cacerts'),
        keystore_password = dict(required=False, default='changeit'),
        cert_location = dict(required=True),
        state = dict(required=False, default='present', choices=['present', 'absent'])
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True
    )

    cert_path = module.params.get('cert_location')
    cert_alias = module.params.get('alias')
    keystore_location = module.params.get('keystore_location')
    keystore_password = module.params.get('keystore_password')
    state = module.params.get('state')

    results = dict(changed=False)
    results['cert_path'] = cert_path
    results['cert_alias'] = cert_alias
    results['keystore_location'] = keystore_location
    results['keystore_password'] = keystore_password

    test_keytool(module)
    test_keystore(module, keystore_location)

    #module.exit_json(**results)

    if state == 'absent':
        if check_cert_present(module, keystore_location, keystore_password, cert_alias):
            delete_cert(module, keystore_location, keystore_password, cert_alias)
        else:
            module.exit_json(changed=False)

    if check_cert_present(module, keystore_location, keystore_password, cert_alias):
        module.exit_json(changed=False)
    else:
        if cert_path:
            import_cert_path(module, cert_path, keystore_location, keystore_password, cert_alias)


from ansible.module_utils.basic import *
if __name__ == '__main__':
    main()
