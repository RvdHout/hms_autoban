<?php

# This file is part of Roundcube "hms_autoban" plugin.

class hms_autoban extends rcube_plugin {
    var $task = 'login';
    var $noframe = true;
    var $noajax = true;
    private $rc;
    
    function init() {
        $this->_load_config();
        $this->add_texts('localization/');
        $this->add_hook('authenticate', array($this, 'authenticate'));		
    }
	
    function _load_config() {
        $rcmail = rcmail::get_instance();
        if (!in_array('global_config', $rcmail->config->get('plugins'))) {
            $this->load_config();
        }
        #Roundcube Brute-force attacks prevention Disabled?
        #print $rcmail->config->get('login_rate_limit');
    }
	
    function authenticate($args) {
        if (!$args['user']) return $args;
        $rcmail = rcmail::get_instance();
        if ($dsn = $rcmail->config->get('db_hms_autoban_dsn')) {
            $db = rcube_db::factory($dsn, '', false);
            $db->set_debug((bool)$rcmail->config->get('sql_debug'));
            $db->db_connect('w');
        } else {
            return $args;
        }
        if ($err = $db->is_error()) return $err;
        $rc_ip = sprintf('%u', ip2long($rcmail->config->get('autoban_webmail_ip', '127.0.0.1')));
        $ip = sprintf('%u', ip2long($this->getVisitorIP()));
        $sql = "SELECT * FROM hm_securityranges WHERE rangename LIKE ? AND (rangelowerip1 = ? AND rangeupperip1 = ? OR rangelowerip2 = ? AND rangeupperip2 = ? OR rangelowerip1 = ? AND rangeupperip1 = ? OR rangelowerip2 = ? AND rangeupperip2 = ?)";
        $res = $db->limitquery($sql, 0, 1, 'Auto-ban: ' . $args['user'] . '%', $rc_ip, $rc_ip, $rc_ip, $rc_ip, $ip, $ip, $ip, $ip);
        if ($err = $db->is_error()) {
            return;
        }
        $ret = $db->fetch_assoc($res);
        if ($ret) {
            $expireson = '';
            $rcmail = rcmail::get_instance();
            $ip = $this->getVisitorIP();
            $log = "HMail Autoban: " . $args['user'] . " --> IP: " . $ip;
            $this->log($log);
            if ($rcmail->config->get('autoban_remote_ip', true)) {
                $ip = sprintf('%u', ip2long($ip));
                #$nb = date('Y-m-d H:i:s');
                $comment = "webmail";
                $sql = "SELECT * FROM hm_settings WHERE settingname = ?";
                $res = $db->limitquery($sql, 0, 1, 'AutoBanMinutes');
                $ret = $db->fetch_assoc($res);
                if (is_array($ret)) {
                    $expires = $ret['settinginteger'] * 60;
                } else {
                    $expires = 3600;
                }
                $expireson = date('Y-m-d H:i:s', time() + $expires);
                #print $expireson;
                #INSERT or UPDATE existing autoban entry
                if (autoban_remote_ip)
                $sql = "INSERT INTO hm_securityranges (rangepriorityid, rangelowerip1, rangeupperip1, rangename, rangeoptions, rangeexpires, rangeexpirestime) VALUES (?, ?, ?, ?, ?, ?, ?) ON DUPLICATE KEY UPDATE rangeexpirestime = ?";
                #$res = $db->query($sql, 20, $ip, $ip, 'Auto-ban: ' . $args['user'] . ' (' . $nb . ')', 0, 1, $expireson, $expireson);
                $res = $db->query($sql, 20, $ip, $ip, 'Auto-ban: ' . $args['user'] . ' (' . $comment . ')', 0, 1, $expireson, $expireson);
                #I think this is added to clear autoban_webmail_ip type entries when you toggle autoban_remote_ip between true/false
                $sql = "DELETE FROM hm_securityranges WHERE rangelowerip1 >= ? AND rangeupperip1 <= ? AND rangename LIKE ?";
                $res = $db->query($sql, $rc_ip, $rc_ip, 'Auto-ban: ' . $args['user'] . '%');
            }
            if ($rcmail->config->get('autoban_custom_errormessage', true)) {
                # Show Custom Brute-force attacks prevention error message.
                $rcmail->output->command('display_message', $this->gettext('autobanned'), 'error');
            } else {
                # Show standard Roundcube Brute-force attacks prevention error message.
                $rcmail->output->command('display_message', $this->gettext('accountlocked'), 'warning');
            }
            $rcmail->output->send('login');
        }
        return $args;
    }
	
    function getVisitorIP() {
        return rcube_utils::remote_addr();
    }
	
    function log($log) {
        $rcmail = rcmail::get_instance();
        if ($rcmail->config->get('autoban_log')) {
			rcmail::write_log('autoban', $log);
        }
    }
}
