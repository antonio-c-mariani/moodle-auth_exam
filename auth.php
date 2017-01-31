<?php
// This file is part of Moodle - http://moodle.org/
//
// Moodle is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// Moodle is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with Moodle.  If not, see <http://www.gnu.org/licenses/>.

/**
 * Moodle Exam auth plugin, reserves username, prevents normal login.
 *
 * @package    auth_exam
 * @author     Antonio Carlos Mariani
 * @copyright  2010 onwards Universidade Federal de Santa Catarina (http://www.ufsc.br)
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

defined('MOODLE_INTERNAL') || die();

require_once($CFG->libdir.'/authlib.php');
require_once($CFG->dirroot.'/user/profile/lib.php');

/**
 * Web service auth plugin.
 */
class auth_plugin_exam extends auth_plugin_base {

    private static $examuserfields = array('firstname', 'lastname', 'email', 'idnumber');

    /**
     * Constructor.
     */
    public function __construct() {
        $this->authtype = 'exam';
        $this->config = new stdClass();

        foreach (self::$examuserfields as $field) {
            $this->config->{'field_updatelocal_' . $field} = 'onlogin';
            $this->config->{'field_lock_' . $field} = true;
        }

        foreach ($this->get_custom_user_profile_fields() as $field) {
            $this->config->{'field_updatelocal_' . $field} = 'onlogin';
            $this->config->{'field_lock_' . $field} = true;
        }
    }

    /**
     * Old syntax of class constructor. Deprecated in PHP7.
     *
     * @deprecated since Moodle 3.1
     */
    public function auth_plugin_exam() {
        debugging('Use of class name as constructor is deprecated', DEBUG_DEVELOPER);
        self::__construct();
    }

    /**
     * Returns true if the username and password work and false if they are
     * wrong or don't exist.
     *
     * @param string $username The username (with system magic quotes)
     * @param string $password The password (with system magic quotes)
     *
     * @return bool Authentication success or failure.
     */
    function user_login($username, $password) {
        return \local_exam_authorization\authorization::authenticate($username, $password);
    }

    /**
     * Returns true if this authentication plugin is 'internal'.
     *
     * @return bool
     */
    function is_internal() {
        return false;
    }

    /**
     * Reads user information from ldap and returns it in array()
     *
     * Function should return all information available. If you are saving
     * this information to moodle user-table you should honor syncronization flags
     *
     * @param string $username username
     *
     * @return mixed array with no magic quotes or false on error
     */
    function get_userinfo($username) {
        $customfields = array();
        foreach (profile_get_custom_fields() as $cf) {
            $customfields[] = $cf->shortname;
        }

        if ($user = \local_exam_authorization\authorization::get_userinfo($username, $customfields)) {
            $userinfo = array();
            $userinfo['username'] = $username;
            foreach (self::$examuserfields as $field) {
                if (isset($user->$field)) {
                    $userinfo[$field] = $user->$field;
                }
            }
            if (isset($user->customfields)) {
                foreach ($user->customfields as $ci) {
                    $userinfo['profile_field_'.$ci->shortname] = $ci->value;
                }
            }
            return $userinfo;
        } else {
            return false;
        }
    }
}
