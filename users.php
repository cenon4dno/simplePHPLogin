<?php
require_once ('database.php');
require_once ('databaseQuery.php');
require_once ('userModel.php');

class Users
{
   public function checkCredentials($username, $password)
   {
      // Initialize vars
      $userId = 0;
      $digest = '';

      try
      {
         $dbh = DatabaseHelpers::getDatabaseConnection();
         $stmt = $dbh->prepare(QUERY_CREDENTIALS);
         $stmt->bindParam(':username', $username, PDO::PARAM_STR);
         $success = $stmt->execute();

         if ($success) {
           $userId = $this->_success($stmt, $password);
         }

         $dbh = null;
      } catch (PDOException $e) {
         $userId = 0;
         $digest = '';
      }

      return array ($userId, $username, $digest);
   }

   private function _success($stmt, $password)
   {
        $userId = 0;

        $userData = $stmt->fetch();
        $digest = $userData['Password'];
        if (crypt ($password, $digest) == $digest) {
           $userId = $userData['UserID'];
        }

        return $userId;
     }
   }
}
?>
