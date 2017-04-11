<?php
/**
 * Created by IntelliJ IDEA.
 * User: rek
 * Date: 2016/7/11
 * Time: 下午3:39
 */

namespace x2ts\ldap;

use x2ts\Component;
use x2ts\Toolkit;

/**
 * Class LDAP
 *
 * @package x2ts
 */
class LDAP extends Component {
    protected static $_conf = [
        'host'           => 'localhost',
        'port'           => 389,
        'dn_base'        => 'ou=staffs,dc=example,dc=com',
        'auth_key'       => 'uid',
        'admin_dn'       => 'cn=admin,dc=example,dc=com',
        'admin_password' => '',
        'search_timeout' => 5,
        'net_timeout'    => 5,
    ];

    public function auth(string $username, string $password): bool {
        $c = ldap_connect($this->conf['host'], $this->conf['port']);
        if (!$c) {
            throw new LDAPException('Cannot connect to LDAP server');
        }
        ldap_set_option($c, LDAP_OPT_PROTOCOL_VERSION, 3);
        $dn = "{$this->conf['auth_key']}={$username},{$this->conf['dn_base']}";
        Toolkit::trace('LDAP DN:' . $dn);
        $r = @ldap_bind($c, $dn, $password);
        ldap_close($c);
        return (bool) $r;
    }

    public function findByUsername(string $username) {
        $c = $this->getLDAPConnection();
        $dn = "{$this->conf['auth_key']}={$username},{$this->conf['dn_base']}";
        Toolkit::trace("LDAP DN: $dn");
        $result = @ldap_read($c, $dn, 'objectClass=person');
        if ($result === false) {
            ldap_close($c);
            return null;
        }
        $entries = ldap_get_entries($c, $result);
        Toolkit::trace($entries);
        ldap_free_result($result);
        ldap_close($c);
        if ($entries['count']) {
            return $entries[0];
        }
        return null;
    }

    public function findByMail(string $mail) {
        $c = $this->getLDAPConnection();
        $dn = "{$this->conf['dn_base']}";
        $filter = "(mail=$mail)";
        $justthese = array("uid", "mail");
        $result = ldap_search($c, $dn, $filter, $justthese);
        $entries = ldap_get_entries($c, $result);
        Toolkit::trace($entries);
        ldap_free_result($result);
        ldap_close($c);
        if ($entries["count"] > 0) {
            return true;
        }
        return false;
    }

    public function changePassword(string $username, string $old_password, string $new_password) {
        $c = $this->getLDAPConnection();
        $dn = "{$this->conf['auth_key']}={$username},{$this->conf['dn_base']}";
        Toolkit::trace("LDAP DN: $dn");
        $r = @ldap_bind($c, $dn, $old_password);
        if (!$r) {
            return false;
        }

        $r = ldap_modify($c, $dn, [
            'userPassword' => $this->hashSSHA($new_password),
        ]);
        ldap_close($c);
        return $r;
    }

    public function overwritePassword(string $username, string $new_password) {
        $c = $this->getLDAPConnection();
        $dn = "{$this->conf['auth_key']}={$username},{$this->conf['dn_base']}";
        Toolkit::trace("LDAP DN: $dn");
        if (!ldap_bind($c, $this->conf['admin_dn'], $this->conf['admin_password'])) {
            return false;
        }
        $entry = ['userPassword' => $this->hashSSHA($new_password)];
        $r = @ldap_modify($c, $dn, $entry);
        if ($r === false && 32 === ldap_errno($c)) {
            $r = ldap_add($c, $dn, $entry);
        }
        ldap_close($c);
        return $r;
    }

    public function addUser(array $user) {
        $c = $this->getLDAPConnection();
        $dn = "{$this->conf['auth_key']}={$user[$this->conf['auth_key']]},{$this->conf['dn_base']}";
        Toolkit::trace("LDAP DN: $dn");
        if (!ldap_bind($c, $this->conf['admin_dn'], $this->conf['admin_password'])) {
            return false;
        }
        Toolkit::trace("adding user");
        Toolkit::trace($user);
        if (ldap_add($c, $dn, $user) === false) {
            throw new LDAPException(ldap_error($c), ldap_errno($c));
        }
        ldap_close($c);
        return true;
    }

    private function getLDAPConnection() {
        $c = ldap_connect($this->conf['host'], $this->conf['port']);
        if (!$c) {
            throw new LDAPException('Cannot connect to LDAP server');
        }
        ldap_set_option($c, LDAP_OPT_PROTOCOL_VERSION, 3);
        ldap_set_option($c, LDAP_OPT_TIMELIMIT, $this->conf['search_timeout']);
        ldap_set_option($c, LDAP_OPT_NETWORK_TIMEOUT, $this->conf['net_timeout']);
        return $c;
    }

    private function hashSSHA(string $password): string {
        $salt = random_bytes(6);
        return '{SSHA}' . base64_encode(sha1($password . $salt, true) . $salt);
    }
}
