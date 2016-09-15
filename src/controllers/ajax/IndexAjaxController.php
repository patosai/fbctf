<?hh // strict

class IndexAjaxController extends AjaxController {
  <<__Override>>
  protected function getFilters(): array<string, mixed> {
    return array(
      'POST' => array(
        'team_id' => FILTER_VALIDATE_INT,
        'teamname' => FILTER_UNSAFE_RAW,
        'password' => FILTER_UNSAFE_RAW,
        'logo' => array(
          'filter' => FILTER_VALIDATE_REGEXP,
          'options' => array('regexp' => '/^[\w+-\/]+={0,2}$/'),
        ),
        'isCustomLogo' => FILTER_VALIDATE_BOOLEAN,
        'logoType'     => FILTER_UNSAFE_RAW,
        'token' => array(
          'filter' => FILTER_VALIDATE_REGEXP,
          'options' => array('regexp' => '/^[\w]+$/'),
        ),
        'names' => FILTER_UNSAFE_RAW,
        'emails' => FILTER_UNSAFE_RAW,
        'action' => array(
          'filter' => FILTER_VALIDATE_REGEXP,
          'options' => array('regexp' => '/^[\w-]+$/'),
        ),
      ),
    );
  }

  <<__Override>>
  protected function getActions(): array<string> {
    return array('register_team', 'register_names', 'login_team');
  }

  <<__Override>>
  protected async function genHandleAction(
    string $action,
    array<string, mixed> $params,
  ): Awaitable<string> {
    switch ($action) {
      case 'none':
        return Utils::error_response('Invalid action', 'index');
      case 'register_team':
        return await $this->genRegisterTeam(
          must_have_string($params, 'teamname'),
          must_have_string($params, 'password'),
          strval(must_have_idx($params, 'token')),
          must_have_string($params, 'logo'),
          must_have_bool($params, 'isCustomLogo'),
          strval(must_have_idx($params, 'logoType')),
          false,
          array(),
          array(),
        );
      case 'register_names':
        $names = json_decode(must_have_string($params, 'names'));
        $emails = json_decode(must_have_string($params, 'emails'));
        invariant(
          is_array($names) &&
          is_array($emails),
          'names and emails should be arrays',
        );

        return await $this->genRegisterTeam(
          must_have_string($params, 'teamname'),
          must_have_string($params, 'password'),
          strval(must_have_idx($params, 'token')),
          must_have_string($params, 'logo'),
          must_have_bool($params, 'isCustomLogo'),
          strval(must_have_idx($params, 'logoType')),
          true,
          $names,
          $emails,
        );
      case 'login_team':
        $team_id = null;
        $login_select = await Configuration::gen('login_select');
        if ($login_select->getValue() === '1') {
          $team_id = must_have_int($params, 'team_id');
        } else {
          $team_name = must_have_string($params, 'teamname');
          $team_exists = await Team::genTeamExist($team_name);
          if ($team_exists) {
            $team = await Team::genTeamByName($team_name);
            $team_id = $team->getId();
          } else {
            return Utils::error_response('Login failed', 'login');
          }
        }
        invariant(is_int($team_id), 'team_id should be an int');

        $password = must_have_string($params, 'password');

        // If we are here, login!
        return await $this->genLoginTeam($team_id, $password);
      default:
        return Utils::error_response('Invalid action', 'index');
    }
  }

  private async function genRegisterTeam(
    string $teamname,
    string $password,
    ?string $token,
    string $logo,
    bool $is_custom_logo,
    ?string $logo_type,
    bool $register_names,
    array<string> $names,
    array<string> $emails,
  ): Awaitable<string> {
    // Check if registration is enabled
    $registration = await Configuration::gen('registration');
    if ($registration->getValue() === '0') {
      return Utils::error_response('Registration failed', 'registration');
    }

    // Check if tokenized registration is enabled
    $registration_type = await Configuration::gen('registration_type');
    if ($registration_type->getValue() === '2') {
      $token_check = await Token::genCheck((string) $token);
      // Check provided token
      if ($token === null || !$token_check) {
        return Utils::error_response('Registration failed', 'registration');
      }
    }

    // Check logo
    $final_logo = $logo;

    if ($is_custom_logo) {
      $logo_data = str_replace(' ', '+', $final_logo);
      $logo_data_unbase64ed = base64_decode($logo_data);

      $name = 'custom-'.time();
      $filename = $name.'.'.$logo_type;
      // '..' is separated for DB storage
      $full_path = '/static/img/customlogo/'.$filename;
      $full_filename = dirname(__FILE__).'/../..'.$full_path;
      file_put_contents($full_filename, $logo_data_unbase64ed);

      $custom_logo_id = await Logo::genCreateCustom($name, $full_path);
      $final_logo = $name;
    }

    $check_exists = await Logo::genCheckExists($final_logo);
    if (!$check_exists) {
      $final_logo = await Logo::genRandomLogo();
    }

    // Check if team name is not empty or just spaces
    if (trim($teamname) === '') {
      return Utils::error_response('Registration failed', 'registration');
    }

    // Trim team name to 20 chars, to avoid breaking UI
    $shortname = substr($teamname, 0, 20);

    // Verify that this team name is not created yet
    $team_exists = await Team::genTeamExist($shortname);
    if (!$team_exists) {
      $password_hash = Team::generateHash($password);
      $team_id =
        await Team::genCreate($shortname, $password_hash, $final_logo);
      if ($team_id) {
        // Store team players data, if enabled
        if ($register_names) {
          for ($i = 0; $i < count($names); $i++) {
            await Team::genAddTeamData($names[$i], $emails[$i], $team_id);
          }
        }
        // If registration is tokenized, use the token
        if ($registration_type->getValue() === '2') {
          invariant($token !== null, 'token should not be null');
          await Token::genUse($token, $team_id);
        }
        // Login the team
        return await $this->genLoginTeam($team_id, $password);
      } else {
        return Utils::error_response('Registration failed', 'registration');
      }
    } else {
      return Utils::error_response('Registration failed', 'registration');
    }
  }

  private async function genLoginTeam(
    int $team_id,
    string $password,
  ): Awaitable<string> {
    // Check if login is enabled
    $login = await Configuration::gen('login');
    if ($login->getValue() === '0') {
      return Utils::error_response('Login failed', 'login');
    }

    // Verify credentials
    $team = await Team::genVerifyCredentials($team_id, $password);

    if ($team) {
      SessionUtils::sessionRefresh();
      if (!SessionUtils::sessionActive()) {
        SessionUtils::sessionSet('team_id', strval($team->getId()));
        SessionUtils::sessionSet('name', $team->getName());
        SessionUtils::sessionSet(
          'csrf_token',
          (string) gmp_strval(
            gmp_init(bin2hex(openssl_random_pseudo_bytes(16)), 16),
            62,
          ),
        );
        SessionUtils::sessionSet(
          'IP',
          must_have_string(Utils::getSERVER(), 'REMOTE_ADDR'),
        );
        if ($team->getAdmin()) {
          SessionUtils::sessionSet('admin', strval($team->getAdmin()));
        }
      }
      if ($team->getAdmin()) {
        $redirect = 'admin';
      } else {
        $redirect = 'game';
      }
      return Utils::ok_response('Login succesful', $redirect);
    } else {
      return Utils::error_response('Login failed', 'login');
    }
  }
}
