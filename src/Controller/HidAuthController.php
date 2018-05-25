<?php

namespace Drupal\social_auth_hid\Controller;

use Drupal\Core\Controller\ControllerBase;
use Drupal\social_api\Plugin\NetworkManager;
use Drupal\social_auth\SocialAuthDataHandler;
use Drupal\social_auth\SocialAuthUserManager;
use Drupal\social_auth_hid\HidAuthManager;
use Symfony\Component\DependencyInjection\ContainerInterface;
use Drupal\Core\Routing\TrustedRedirectResponse;
use Symfony\Component\HttpFoundation\RequestStack;

/**
 * Returns responses for Social Auth Hid module routes.
 */
class HidAuthController extends ControllerBase {

  /**
   * The network plugin manager.
   *
   * @var \Drupal\social_api\Plugin\NetworkManager
   */
  private $networkManager;

  /**
   * The user manager.
   *
   * @var \Drupal\social_auth\SocialAuthUserManager
   */
  private $userManager;

  /**
   * The google authentication manager.
   *
   * @var \Drupal\social_auth_hid\HidAuthManager
   */
  private $hidManager;

  /**
   * Used to access GET parameters.
   *
   * @var \Symfony\Component\HttpFoundation\RequestStack
   */
  private $request;

  /**
   * The Social Auth Data Handler.
   *
   * @var \Drupal\social_auth\SocialAuthDataHandler
   */
  private $dataHandler;

  /**
   * HidAuthController constructor.
   *
   * @param \Drupal\social_api\Plugin\NetworkManager $network_manager
   *   Used to get an instance of social_auth_google network plugin.
   * @param \Drupal\social_auth\SocialAuthUserManager $user_manager
   *   Manages user login/registration.
   * @param \Drupal\social_auth_hid\HidAuthManager $hid_manager
   *   Used to manage authentication methods.
   * @param \Symfony\Component\HttpFoundation\RequestStack $request
   *   Used to access GET parameters.
   * @param \Drupal\social_auth\SocialAuthDataHandler $data_handler
   *   SocialAuthDataHandler object.
   */
  public function __construct(NetworkManager $network_manager,
                              SocialAuthUserManager $user_manager,
                              HidAuthManager $hid_manager,
                              RequestStack $request,
                              SocialAuthDataHandler $data_handler) {

    $this->networkManager = $network_manager;
    $this->userManager = $user_manager;
    $this->hidManager = $hid_manager;
    $this->request = $request;
    $this->dataHandler = $data_handler;

    // Sets the plugin id.
    $this->userManager->setPluginId('social_auth_hid');

    // Sets the session keys to nullify if user could not logged in.
    $this->userManager->setSessionKeysToNullify(['access_token', 'oauth2state']);
  }

  /**
   * {@inheritdoc}
   */
  public static function create(ContainerInterface $container) {
    return new static(
      $container->get('plugin.network.manager'),
      $container->get('social_auth.user_manager'),
      $container->get('social_auth_hid.manager'),
      $container->get('request_stack'),
      $container->get('social_auth.data_handler')
    );
  }

  /**
   * Response for path 'user/login/hid'.
   *
   * Redirects the user to HID for authentication.
   */
  public function redirectToHid() {
    /* @var \League\OAuth2\Client\Provider\Hid false $hid */
    $hid = $this->networkManager->createInstance('social_auth_hid')->getSdk();

    // If hid client could not be obtained.
    if (!$hid) {
      drupal_set_message($this->t('Social Auth Humanitarian ID not configured properly. Contact site administrator.'), 'error');
      return $this->redirect('user.login');
    }

    // Destination parameter specified in url.
    $destination = $this->request->getCurrentRequest()->get('destination');
    // If destination parameter is set, save it.
    if ($destination) {
      $this->userManager->setDestination($destination);
    }

    // HID service was returned, inject it to $hidManager.
    $this->hidManager->setClient($hid);

    // Generates the URL where the user will be redirected for HID login.
    // If the user did not have email permission granted on previous attempt,
    // we use the re-request URL requesting only the email address.
    $hid_login_url = $this->hidManager->getAuthorizationUrl();

    $state = $this->hidManager->getState();

    $this->dataHandler->set('oauth2state', $state);

    return new TrustedRedirectResponse($hid_login_url);
  }

  /**
   * Response for path 'user/login/hid/callback'.
   *
   * HID returns the user here after user has authenticated in HID.
   */
  public function callback() {
    // Checks if user cancel login via HID.
    $error = $this->request->getCurrentRequest()->get('error');
    if ($error == 'access_denied') {
      drupal_set_message($this->t('You could not be authenticated.'), 'error');
      return $this->redirect('user.login');
    }

    /* @var \League\OAuth2\Client\Provider\Hid|false $hid */
    $hid = $this->networkManager->createInstance('social_auth_hid')->getSdk();

    // If HID client could not be obtained.
    if (!$hid) {
      drupal_set_message($this->t('Social Auth Humanitarian ID not configured properly. Contact site administrator.'), 'error');
      return $this->redirect('user.login');
    }

    $state = $this->dataHandler->get('oauth2state');

    // Retrieves $_GET['state'].
    $retrievedState = $this->request->getCurrentRequest()->query->get('state');
    if (empty($retrievedState) || ($retrievedState !== $state)) {
      $this->userManager->nullifySessionKeys();
      drupal_set_message($this->t('Humanitarian ID login failed. Unvalid OAuth2 state.'), 'error');
      return $this->redirect('user.login');
    }

    // Saves access token to session.
    $this->dataHandler->set('access_token', $this->hidManager->getAccessToken());

    $this->hidManager->setClient($hid)->authenticate();

    // Gets user's info from HID API.
    if (!$hid_profile = $this->hidManager->getUserInfo()) {
      drupal_set_message($this->t('Humanitarian ID login failed, could not load Humanitarian ID profile. Contact site administrator.'), 'error');
      return $this->redirect('user.login');
    }

    // Gets (or not) extra initial data.
    $data = $this->userManager->checkIfUserExists($hid_profile->getId()) ? NULL : $this->hidManager->getExtraDetails();

    // If user information could be retrieved.
    return $this->userManager->authenticateUser($hid_profile->getName(), $hid_profile->getEmail(), $hid_profile->getId(), $this->hidManager->getAccessToken(), $hid_profile->getAvatar(), $data);
  }

}
