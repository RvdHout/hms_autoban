<?php
# This file is part of Roundcube "hms_autoban" plugin.
class hms_autoban extends rcube_plugin
{
    var $task = 'login';
    var $noframe = true;
    var $noajax = true;
    private $rc;

    function init()
    {
        $this->_load_config();
        $this->add_texts('localization/');
        $this->add_hook('authenticate', array($this, 'authenticate'));
    }

    function _load_config()
    {
        $rcmail = rcmail::get_instance();
        if (!in_array('global_config', $rcmail->config->get('plugins')))
        {
            $this->load_config();
        }
    }

    function authenticate($args)
    {
        if (!$args['user']) return $args;
        $rcmail = rcmail::get_instance();
        if ($dsn = $rcmail->config->get('db_hms_autoban_dsn'))
        {
            $db = rcube_db::factory($dsn, '', false);
            $db->set_debug((bool)$rcmail->config->get('sql_debug'));
            $db->db_connect('w');
        }
        else
        {
            return $args;
        }
        if ($err = $db->is_error()) return $err;
        $rc_ip = sprintf('%u', ip2long($rcmail->config->get('autoban_webmail_ip', '127.0.0.1')));
        $ip = sprintf('%u', ip2long($this->getVisitorIP()));
        $sql = "SELECT * FROM hm_securityranges WHERE rangename LIKE ? AND ((rangelowerip1 = ? AND rangeupperip1 = ? AND rangelowerip2 IS NULL AND rangeupperip2 IS NULL) OR (rangelowerip1 = ? AND rangeupperip1 = ? AND rangelowerip2 IS NULL AND rangeupperip2 IS NULL))";
        $res = $db->limitquery($sql, 0, 1, 'Auto-ban: ' . $args['user'] . '%', $rc_ip, $rc_ip, $ip, $ip);
        if ($err = $db->is_error())
        {
            return;
        }
        $ret = $db->fetch_assoc($res);
        if ($ret)
        {
            # set defaults
            $rangeid = 0;
            $expires = 3600;
            $expireson = date('Y-m-d H:i:s', time() + $expires);
            if (is_array($ret))
            {
                $rangeid = $ret['rangeid'];
                $expireson = $ret['rangeexpirestime'];
            }
            $ip = $this->getVisitorIP();
            $log = "HMail Autoban: " . $args['user'] . " --> IP: " . $ip;
            $this->log($log);
            if ($rcmail->config->get('autoban_remote_ip', true))
            {
                $ip = sprintf('%u', ip2long($ip));
                $comment = "webmail";
                $sql = "SELECT * FROM hm_settings WHERE settingname = ?";
                $res = $db->limitquery($sql, 0, 1, 'AutoBanMinutes');
                $ret = $db->fetch_assoc($res);
                if (is_array($ret))
                {
                    $expires = $ret['settinginteger'] * 60;
                }
                # insert or update existing autoban entry
                if ($rcmail->config->get('autoban_update_expirytime', true))
                {
                    $expireson = date('Y-m-d H:i:s', time() + $expires);
                    $sql = "INSERT INTO hm_securityranges (rangepriorityid, rangelowerip1, rangeupperip1, rangename, rangeoptions, rangeexpires, rangeexpirestime) VALUES (?, ?, ?, ?, ?, ?, ?) ON DUPLICATE KEY UPDATE rangeexpirestime = ?";
                    $res = $db->query($sql, 20, $ip, $ip, 'Auto-ban: ' . $args['user'] . ' - ' . long2ip($ip) . ' (' . $comment . ')', 0, 1, $expireson, $expireson);
                }
                else
                {
                    $sql = "INSERT INTO hm_securityranges (rangepriorityid, rangelowerip1, rangeupperip1, rangename, rangeoptions, rangeexpires, rangeexpirestime) VALUES (?, ?, ?, ?, ?, ?, ?) ON DUPLICATE KEY UPDATE rangeid = ?";
                    $res = $db->query($sql, 20, $ip, $ip, 'Auto-ban: ' . $args['user'] . ' - ' . long2ip($ip) . ' (' . $comment . ')', 0, 1, $expireson, $rangeid);
                }
                # delete autoban_webmail_ip type entries when you toggle autoban_remote_ip between true/false
                $sql = "DELETE FROM hm_securityranges WHERE rangelowerip1 = ? AND rangeupperip1 = ? AND rangename LIKE ?";
                $res = $db->query($sql, $rc_ip, $rc_ip, 'Auto-ban: ' . $args['user'] . '%');
            }
            if ($rcmail->config->get('autoban_custom_errormessage', true))
            {
                # show custom brute-force attacks prevention error message.
                $rcmail->output->command('display_message', $this->gettext(['name' => 'autobanned', 'vars' => ['expireson' => date("H:i:s", strtotime($expireson)) ]]), 'error');
            }
            else
            {
                # show standard roundcube brute-force attacks prevention error message.
                $rcmail->output->command('display_message', $rcmail->gettext('accountlocked'), 'warning');
            }
            $rcmail->output->send('login');
        }
        return $args;
    }

    function getVisitorIP()
    {
        return rcube_utils::remote_addr();
    }

    function log($log)
    {
        $rcmail = rcmail::get_instance();
        if ($rcmail->config->get('autoban_log'))
        {
            rcmail::write_log('autoban', $log);
        }
    }
}
?>
