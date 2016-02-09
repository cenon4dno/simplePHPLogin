<?php
require_once ('siteInfo.php');
require_once ('dataInfo.php');
require_once ('database.php');
require_once ('users.php');
require_once ('pages.php');

class Authentication
{
  private function _isSecuredPage($page)
  {
     return $page === Page::INDEX;
  }

  private function _checkSession()
  {
    if ($this->_validateCookie() && $this->_validateUsername()) {
       session_regenerate_id ();

       if (!isset ($_SESSION[SITE_NAME]['userId'])) {
          $_SESSION[SITE_NAME]['userId'] = $_COOKIE[SITE_NAME]['userId'];
       }

       if (!$this->_isSecuredPage($page) && $action != 'logout') {
          header ('Location: ./');
          exit;
       }
    } else {
       if ($page != Page::LOGIN) {
          header ('Location: login.php');

          exit;
       }
    }
  }

  private function _validateUsername()
  {
    $validUsername = false;

    if(!isset ($_COOKIE[SITE_NAME]['username']) ||
      (isset ($_COOKIE[SITE_NAME]['username']) &&
      Users::checkCredentials($_COOKIE[SITE_NAME]['username'],
      $_COOKIE[SITE_NAME]['digest']))) {
            $validUsername = true;
      }

    return $validUsername;
  }

  private function _validateCookie()
  {
    $validCookie = false;

    if (isset ($_COOKIE[SITE_NAME]['userId']) &&
        crypt($_SERVER['REMOTE_ADDR'] . $_SERVER['HTTP_USER_AGENT'],
              $_COOKIE[SITE_NAME]['secondDigest']) ===
        $_COOKIE[SITE_NAME]['secondDigest'] ) {
          $validCookie = true;
        }

    return $validCookie;
  }

  public function checkLoggedIn($page)
  {
     //Initialize variables
     $loginDiv = '';
     $action = '';

     if (isset($_POST['action'])) {
        $action = stripslashes ($_POST['action']);
     }

     session_start ();

     $this->_checkSession();

     if ($page === Page::LOGIN && $action != '') {
        switch ($action)
        {
           case 'login':
              $loginDiv = $this->_loginAction();
              break;
           case 'logout':
              $loginDiv = $this->_logoutAction();
              break;
        }
     }

     return $loginDiv;
  }

  private function loginAction() {
    $userData = Users::checkCredentials(
      stripslashes ($_POST['login-username']),
      stripslashes ($_POST['password'])
    );

    if ($userData[0] != 0)
    {
       $_SESSION[SITE_NAME]['userId'] = $userData[0];
       $_SESSION[SITE_NAME]['ip'] = $_SERVER['REMOTE_ADDR'];
       $_SESSION[SITE_NAME]['userAgent'] = $_SERVER['HTTP_USER_AGENT'];
       if (isset ($_POST['remember'])) {
          $this->setCookie();
       } else {
          $this->unsetCookie();
       }

       header ('Location: ./');

       exit;
    } else {
       return '<div id="login-box" class="error">The username or password ' .
                   'you entered is incorrect.</div>';
    }
  }

  private function _setCookie($userData)
  {
    setcookie(SITE_NAME . '[userId]', $userData[0], time () + (3600 * 168));
    setcookie(SITE_NAME . '[username]', $userData[1], time () + (3600 * 168));
    setcookie(SITE_NAME . '[digest]', $userData[2], time () + (3600 * 168));
    setcookie(SITE_NAME . '[secondDigest]', DatabaseHelpers::blowfishCrypt(
        $_SERVER['REMOTE_ADDR'] . $_SERVER['HTTP_USER_AGENT'], 10
      ),
      time () + (3600 * 168)
    );
  }

  private function _unsetCookie($userData)
  {
    setcookie(SITE_NAME . '[userId]', $userData[0], false);
    setcookie(SITE_NAME . '[username]', '', false);
    setcookie(SITE_NAME . '[digest]', '', false);
    setcookie(SITE_NAME . '[secondDigest]',
    DatabaseHelpers::blowfishCrypt(
      $_SERVER['REMOTE_ADDR'] . $_SERVER['HTTP_USER_AGENT'], 10
      ),
      time () + (3600 * 168)
    );
  }

  private function _logoutAction()
  {
    // Destroy all session and cookie variables
    $_SESSION = array ();
    setcookie(SITE_NAME . '[userId]', '', time () - (3600 * 168));
    setcookie(SITE_NAME . '[username]', '', time () - (3600 * 168));
    setcookie(SITE_NAME . '[digest]', '', time () - (3600 * 168));
    setcookie(SITE_NAME . '[secondDigest]', '', time () - (3600 * 168));

    // Destory the session
    session_destroy ();

    return '<div id="login-box" class="info">Thank you. Come again!</div>';
  }
}
?>
