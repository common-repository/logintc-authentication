<?php
/**
 * Plugin Name: LoginTC Two Factor Authentication
 * Plugin URI: https://github.com/logintc/logintc-wordpress
 * Description: Two-factor authentication for WordPress by <a href="https://www.logintc.com/">LoginTC</a>.
 * Author: Cyphercor Inc.
 * Version: 1.0.0
 * Author URI: https://www.logintc.com
 * License: BSD-3-Clause
 * License URI: http://opensource.org/licenses/BSD-3-Clause
 */

/*

(The BSD 3-Clause License)

Copyright (c) 2014, Cyphercor Inc.
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:
    * Redistributions of source code must retain the above copyright
      notice, this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above copyright
      notice, this list of conditions and the following disclaimer in the
      documentation and/or other materials provided with the distribution.
    * Neither the name of the Cyphercor Inc. nor the
      names of its contributors may be used to endorse or promote products
      derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL CYPHERCOR INC. BE LIABLE FOR ANY
DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.


*/

require_once( 'logintc-php/LoginTC.php' );

const LOGINTC_RE_VALID_DOMAIN_ID = "/^[0-9abcdef]{40}$/";
const LOGINTC_RE_VALID_API_KEY = "/^[0-9a-z]{64}$/i";
const LOGINTC_RE_VALID_IP = "/^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$/";
const LOGINTC_RE_VALID_HOSTNAME = "/^(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\-]*[A-Za-z0-9])$/";
const LOGINTC_RE_VALID_TIMEOUT = "/^([1-9]|[1-9][0-9]|[1-9][0-9][0-9])$/";

function logintc_request( $username ) {
    ?>

<html>
<head>
<?php
    global $wp_version;
    if ( version_compare( $wp_version, '3.2', '<=' ) ) {
?>
    <link rel="stylesheet" type="text/css" href="<?php echo admin_url( 'css/login.css' ); ?>" />
<?php
    } else {
?>
    <link rel="stylesheet" type="text/css" href="<?php echo admin_url( 'css/wp-admin.css' ); ?>" />
<?php
    }
?>
    <link rel="stylesheet" type="text/css" href="<?php echo plugins_url( 'css/login.css', __FILE__ ); ?>" />
</head>
<body class="login">
    <div id="login">
        <h1>
            <a href="http://wordpress.org/" title="Powered by WordPress"><?php echo get_bloginfo( 'name' ); ?></a>
        </h1>
        <img src="<?php echo plugins_url( 'img/loader.gif', __FILE__ ); ?>">
        <h3>
            A LoginTC request has been sent to your smart device. Approve for access.
        </h3>
        <p>
            <a href="wp-login.php">Cancel</a>
        </p>
        <form id="auto-post" action="<?php echo esc_url( site_url( 'wp-login.php', 'login_post' ) ) ?>" method="post">
            <input type="hidden" name="auth_request" value="1" />
            <input type="hidden" name="username" value="<?php echo $username; ?>" />
        </form>
        <script>
            document.getElementById("auto-post").submit(); 
        </script>
    </div>
</body>
</html>

    <?php
}

function logintc_get_option( $key, $default = '', $use_cache = true ) {
    if ( is_multisite() ) {
        return get_site_option( $key, $default, $use_cache );
    }
    else {
        return get_option( $key, $default );
    }
}

function logintc_auth( $username ) {
    try {
        $user = new WP_User( 0, $username );
        
        $api_key = logintc_get_option( 'logintc_api_key' );
        
        $logintc_admin_host = logintc_get_option( 'logintc_admin_host' );

        $logintc = new LoginTC( $api_key, $logintc_admin_host );
    
        $domain_id = logintc_get_option( 'logintc_domain_id' );
        
        $domain_attribute_ip = logintc_get_option( 'logintc_domain_attribute_ip' );
    
        $attributes = array();

        if ( $domain_attribute_ip === 'true' ) {
            $attributes[] = new DomainAttribute('IP Address', $_SERVER['REMOTE_ADDR']);
        }
        
        $session = $logintc->createSessionWithUsername( $domain_id, $username, $attributes );
    
        $t = time();
        $timeout = logintc_get_option( 'logintc_timeout' );
        $response = null;
        while ( ( time() - $t ) < $timeout ) {
    
            $polled_session = $logintc->getSession( $domain_id, $session->getId() );
    
            if ( $polled_session->getState() != 'pending' ) {
                break;
            }
    
            sleep( 1 ); // wait 1s
        }

        if ( $polled_session->getState() === 'approved' ) {
            wp_set_auth_cookie( $user->ID );
            wp_safe_redirect( admin_url() );
        }
    } catch ( ApiLoginTCException $ale ) {
        return new WP_Error( 'logintc_authentication_failed', __( '<strong>ERROR</strong>: ' . $ale->getErrorMessage() ) );
    } catch ( Exception $e ) {
        return new WP_Error( 'logintc_authentication_failed', __( '<strong>ERROR</strong>: ' . $e->getMessage() ) );
    }

    return new WP_Error( 'logintc_authentication_failed', __( '<strong>ERROR</strong>: LoginTC authentication failed or timed out.' )  );

}

function logintc_get_roles() {
    global $wp_roles;
    
    if ( ! isset( $wp_roles ) ) {
        $wp_roles = new WP_Roles();
    }

    return $wp_roles;
}

function logintc_user_has_role_for_auth( $user ) {
    if ( empty( $user->roles ) ) {
        return true;
    }

    global $wp_roles;
    
    $all_roles = $wp_roles->get_names();

    $selected_roles = logintc_get_option( 'logintc_roles', $all_roles );
    
    foreach ( $user->roles as $role ) {
        if ( array_key_exists( $role, $selected_roles ) ) {
            return true;
        }
    }
    
    return false;
}

function logintc_authenticate_user( $user='', $username = '', $password='' ) {

    if ( ( defined( 'XMLRPC_REQUEST' ) && XMLRPC_REQUEST ) || ( defined( 'APP_REQUEST' ) && APP_REQUEST ) ) {
        return;
    }

    if ( logintc_get_option( 'logintc_api_key', '' ) === '' || logintc_get_option( 'logintc_domain_id', '' ) === '' || logintc_get_option( 'logintc_admin_host', '' ) === '' ) {
        return;
    }

    if ( strlen( $username ) > 0 ) {

        $user = new WP_User(0, $username);
        if ( ! $user ) {
            return;
        }
        
        if ( ! logintc_user_has_role_for_auth( $user ) ) {
            return;
        }

        remove_action( 'authenticate', 'wp_authenticate_username_password', 20 );

        $ret = wp_authenticate_username_password( NULL, $username, $password );
        if ( is_wp_error( $ret ) ) {
            return $ret;
        } else {
            logintc_request( $username );
            exit;
        }

    }

    if ( $_POST['auth_request'] == 1 ) {
        $username = $_POST['username'];
        
        return logintc_auth( $username );
    }

}

function logintc_settings_page() {
?>
<div class="wrap">
    <h2>LoginTC Two-Factor Authentication</h2>
    <form action="options.php" method="post">
    <?php settings_fields( 'logintc_settings' ); ?>
    <?php do_settings_sections( 'logintc_settings' ); ?>
        <p class="submit">
            <input name="Submit" type="submit" class="button primary-button" value="<?php esc_attr_e( 'Save Changes' ); ?>" />
        </p>
    </form>
</div>
<?php
}

function logintc_settings_api_key() {
    $api_key = esc_attr( logintc_get_option( 'logintc_api_key' ) );
    echo '<input id="logintc_api_key" name="logintc_api_key" size="64" type="text" value="' . $api_key . '" /><p>The 64-character organization API key</p>';
}

function logintc_settings_domain_id() {
    $domain_id = esc_attr( logintc_get_option( 'logintc_domain_id' ) );
    echo '<input id="logintc_domain_id" name="logintc_domain_id" size="40" type="text" value="' . $domain_id . '" /><p>The 40-character domain ID</p>';
}

function logintc_settings_admin_host() {
    $host = esc_attr( logintc_get_option( 'logintc_admin_host', 'cloud.logintc.com' ) );

    echo '<input id="logintc_admin_host" name="logintc_admin_host" size="40" type="text" value="' . $host . '" /><p>Hostname or IP address of the LoginTC manager</p>';
}

function logintc_settings_timeout() {
    $timeout = esc_attr( logintc_get_option( 'logintc_timeout', 60 ) );

    echo '<input id="logintc_timeout" name="logintc_timeout" size="3" type="text" value="' . $timeout . '" /><p>Number of seconds to allow for an authentication request to be approved</p>';
}

function logintc_settings_roles() {
    $wp_roles = logintc_get_roles();
    
    $all_roles = $wp_roles->get_names();

    $selected_roles = logintc_get_option( 'logintc_roles', $all_roles );

    foreach ( $all_roles as $role => $role_name ) {
?>
<input  id="logintc_roles" 
        name="logintc_roles[<?php echo $role; ?>]" type="checkbox" value="<?php echo $role_name; ?>"
        <?php if ( in_array( $role_name, $selected_roles ) ) { echo 'checked'; } ?> />
        <?php echo $role_name; ?>
<br>
<?php
    }
}

function logintc_settings_domain_attribute_ip() {
    $domain_attribute_ip = logintc_get_option( 'logintc_domain_attribute_ip', 'true' );
    
    if ( $domain_attribute_ip == null ) {
        $domain_attribute_ip = 'false';
    }

?>
<label for="logintc_domain_attribute_ip">
<input id="logintc_domain_attribute_ip" 
        name="logintc_domain_attribute_ip" type="checkbox" value="true"
        <?php if ( $domain_attribute_ip === 'true' ) { echo 'checked'; } ?> />
        <span>Check to display the user's IP Address on the LoginTC request</span>
</label>
<br>
<?php
}

function logintc_settings_disable_xmlrpc() {
    $disable_xmlrpc = logintc_get_option( 'logintc_disable_xmlrpc', 'true' );
    
    if ( $disable_xmlrpc == null ) {
        $disable_xmlrpc = 'false';
    }
    
?>
<label for="logintc_disable_xmlrpc">
<input id="logintc_disable_xmlrpc" 
        name="logintc_disable_xmlrpc" type="checkbox" value="true"
        <?php if ( $disable_xmlrpc === 'true' ) { echo 'checked'; } ?> />
        <span style="color: #ff1414;">Enabling this option will bypass two-factor authentication completely when using a mobile app.</span>
</label>
<br>
<?php
}

function logintc_settings_text() {
    echo '<p>The LoginTC <a target="_blank" href="https://www.logintc.com/docs/connectors/wordpress">WordPress Connector</a> enables two-factor authentication for your WordPress logins.</p>';
}

function logintc_api_key_validate( $api_key ) {
    if ( ! preg_match( LOGINTC_RE_VALID_API_KEY, $api_key ) ) {
        add_settings_error( 'logintc_api_key', '', 'API key is not valid' );
        return '';
    } else {
        return $api_key;
    }
}

function logintc_domain_id_validate( $domain_id ) {
    if ( ! preg_match( LOGINTC_RE_VALID_DOMAIN_ID, $domain_id ) ) {
        add_settings_error( 'logintc_domain_id', '', 'Domain ID is not valid' );
        return '';
    } else {
        return $domain_id;
    }
}

function logintc_admin_host_validate( $admin_host ) {
    if ( preg_match( LOGINTC_RE_VALID_HOSTNAME, $admin_host ) != 1 && preg_match( LOGINTC_RE_VALID_IP, $admin_host ) != 1 ) {
        add_settings_error( 'logintc_admin_host', '', 'Admin Host is not valid' );
        return '';
    } else {
        return $admin_host;
    }
}

function logintc_timeout_validate( $timeout ) {
    if ( preg_match( LOGINTC_RE_VALID_TIMEOUT, $timeout ) != 1 ) {
        add_settings_error( 'logintc_timeout', '', 'Timeout is not valid' );
        return '';
    } else {
        return $timeout;
    }
}

function logintc_roles_validate( $roles ) {
    if ( ! is_array( $roles ) || empty( $roles ) ) {
        return array();
    }

    $wp_roles = logintc_get_roles();

    $all_roles = $wp_roles->get_names();

    foreach ( $roles as $role ) {
        if ( ! in_array( $role, $all_roles ) ) {
            unset( $roles[$role] );
        }
    }
    return $roles;
}

function logintc_domain_attribute_ip_validate( $domain_attribute_ip ) {
    if ( $domain_attribute_ip != null && $domain_attribute_ip !== 'true' ) {
        add_settings_error( 'logintc_domain_attribute_ip', '', 'IP domain attribute is not valid' );
    }
    
    if ( $domain_attribute_ip == null ) {
        $domain_attribute_ip = 'false';
    }

    return $domain_attribute_ip;
}

function logintc_disable_xmlrpc_validate( $disable_xmlrpc ) {
    if ( $disable_xmlrpc != null && $disable_xmlrpc !== 'true' ) {
        add_settings_error( 'logintc_disable_xmlrpc', '', 'XML-RPC is not valid' );
    }
    
    if ( $disable_xmlrpc == null ) {
        $disable_xmlrpc = 'false';
    }

    return $disable_xmlrpc;
}

function logintc_add_site_option_safe( $key, $value = '') {
    if ( logintc_get_option( $option ) === FALSE ) {
        add_site_option( $option, $value );
    }
}

function logintc_admin_init() {
    if ( is_multisite() ) {
        $wp_roles = logintc_get_roles();
    
        $all_roles = $wp_roles->get_names();
            
        logintc_add_site_option_safe('logintc_api_key', '');
        logintc_add_site_option_safe('logintc_domain_id', '');
        logintc_add_site_option_safe('logintc_admin_host', 'cloud.logintc.com');
        logintc_add_site_option_safe('logintc_timeout', 60);
        logintc_add_site_option_safe('logintc_roles', $all_roles);
        logintc_add_site_option_safe('logintc_domain_attribute_ip', 'true');
        logintc_add_site_option_safe('logintc_disable_xmlrpc', 'true');
    } else {
        add_settings_section( 'logintc_settings', 'Main Settings', 'logintc_settings_text', 'logintc_settings' );
        add_settings_field( 'logintc_api_key', 'API key', 'logintc_settings_api_key', 'logintc_settings', 'logintc_settings' );
        add_settings_field( 'logintc_domain_id', 'Domain ID', 'logintc_settings_domain_id', 'logintc_settings', 'logintc_settings' );
        add_settings_field( 'logintc_admin_host', 'Admin Host', 'logintc_settings_admin_host', 'logintc_settings', 'logintc_settings' );
        add_settings_field( 'logintc_timeout', 'Timeout (s)', 'logintc_settings_timeout', 'logintc_settings', 'logintc_settings' );
        add_settings_field( 'logintc_roles', 'Enable LoginTC for roles', 'logintc_settings_roles', 'logintc_settings', 'logintc_settings' );
        add_settings_field( 'logintc_domain_attribute_ip', 'Configure what users see on the LoginTC request', 'logintc_settings_domain_attribute_ip', 'logintc_settings', 'logintc_settings' );
        add_settings_field( 'logintc_disable_xmlrpc', 'Disable XML-RPC', 'logintc_settings_disable_xmlrpc', 'logintc_settings', 'logintc_settings' );
        register_setting( 'logintc_settings', 'logintc_api_key', 'logintc_api_key_validate' );
        register_setting( 'logintc_settings', 'logintc_domain_id', 'logintc_domain_id_validate' );
        register_setting( 'logintc_settings', 'logintc_admin_host', 'logintc_admin_host_validate' );
        register_setting( 'logintc_settings', 'logintc_timeout', 'logintc_timeout_validate' );
        register_setting( 'logintc_settings', 'logintc_roles', 'logintc_roles_validate' );
        register_setting( 'logintc_settings', 'logintc_domain_attribute_ip', 'logintc_domain_attribute_ip_validate' );
        register_setting( 'logintc_settings', 'logintc_disable_xmlrpc', 'logintc_disable_xmlrpc_validate' );
    }
}

function logintc_wpmu_options() {

?>
<h3>LoginTC</h3>

<p><?php logintc_settings_text(); ?></p>
<table class="form-table">
    <tr><th>API key</th><td><?php logintc_settings_api_key(); ?></td></tr>
    <tr><th>Domain ID</th><td><?php logintc_settings_domain_id(); ?></td></tr>
    <tr><th>Admin host</th><td><?php logintc_settings_admin_host(); ?></td></tr>
    <tr><th>Timeout (s)</th><td><?php logintc_settings_timeout(); ?></td></tr>
    <tr><th>Enable LoginTC for roles</th><td><?php logintc_settings_roles(); ?></td></tr>
    <tr><th>Enable IP address domain attribute</th><td><?php logintc_settings_domain_attribute_ip(); ?></td></tr>
    <tr><th>Disable XML-RPC</th><td><?php logintc_settings_disable_xmlrpc(); ?></td></tr>
</table>
<?php
    }

function logintc_update_wpmu_options() {
    // update vlaue without validation.. 
    if ( isset( $_POST['logintc_api_key'] ) ) {
        $api_key = $_POST['logintc_api_key'];
        update_site_option( 'logintc_api_key', $api_key );
    }

    if ( isset( $_POST['logintc_domain_id'] ) ) {
        $domain_id = $_POST['logintc_domain_id'];
        update_site_option( 'logintc_domain_id', $domain_id );
    }

    if ( isset( $_POST['logintc_admin_host'] ) ) {
        $admin_host = $_POST['logintc_admin_host'];
        update_site_option( 'logintc_admin_host', $admin_host );
    }

    if ( isset( $_POST['logintc_timeout'] ) ) {
        $timeout = $_POST['logintc_timeout'];
        update_site_option( 'logintc_timeout', $timeout );
    }
    
    if ( isset( $_POST['logintc_roles'] ) ) {
        $selected_roles = $_POST['logintc_roles'];
        update_site_option( 'logintc_roles', $selected_roles );
    }
    
    if ( isset( $_POST['logintc_domain_attribute_ip'] ) ) {
        $domain_attribute_ip = $_POST['logintc_domain_attribute_ip'];
        update_site_option( 'logintc_domain_attribute_ip', $domain_attribute_ip );
    } else {
        update_site_option( 'logintc_domain_attribute_ip', 'false' );
    }
    
    if ( isset( $_POST['logintc_disable_xmlrpc'] ) ) {
        $disable_xmlrpc = $_POST['logintc_disable_xmlrpc'];
        update_site_option( 'logintc_disable_xmlrpc', $disable_xmlrpc );
    } else {
        update_site_option( 'logintc_disable_xmlrpc', 'false' );
    }
}

function logintc_add_page() {
    if ( ! is_multisite() ) {
        add_options_page( 'LoginTC Two-Factor', 'LoginTC Two-Factor', 'manage_options', 'logintc_wordpress', 'logintc_settings_page' );
    }
}

function logintc_add_link( $links, $file ) {
    static $this_plugin;
    if ( ! $this_plugin ) {
        $this_plugin = plugin_basename( __FILE__ );
    }

    if ( $file == $this_plugin ) {
        $settings_link = '<a href="' . admin_url( 'options-general.php?page=logintc_wordpress' ) . '">' . __( "Settings", "logintc_wordpress" ) . '</a>';
        array_unshift( $links, $settings_link );
    }
    return $links;
}

if( logintc_get_option( 'logintc_disable_xmlrpc', 'true' ) === 'true' ) {
    add_filter( 'xmlrpc_enabled', '__return_false' );
}

add_filter( 'authenticate', 'logintc_authenticate_user', 10, 3 );

add_action( 'admin_menu', 'logintc_add_page' );
add_action( 'admin_init', 'logintc_admin_init' );

add_action('wpmu_options', 'logintc_wpmu_options');
add_action('update_wpmu_options', 'logintc_update_wpmu_options');

add_filter( 'plugin_action_links', 'logintc_add_link', 10, 2 );
