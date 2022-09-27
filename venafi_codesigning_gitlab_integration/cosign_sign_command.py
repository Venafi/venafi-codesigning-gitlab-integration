from dataclasses import dataclass
from venafi_codesigning_gitlab_integration import utils
import envparse
import tempfile
import logging
import sys
import base64
import secrets

config_schema = dict(
    TPP_AUTH_URL=str,
    TPP_HSM_URL=str,
    TPP_USERNAME=str,
    TPP_PASSWORD=dict(cast=str, default=None),
    TPP_PASSWORD_BASE64=dict(cast=str, default=None),

    CERTIFICATE_LABEL=str,
    IMAGE=str,

    EXTRA_TRUSTED_TLS_CA_CERTS=dict(cast=str, default=None),
    VENAFI_CLIENT_TOOLS_DIR=dict(cast=str, default=None),
    ISOLATE_SESSIONS=dict(cast=bool, default=True),
)


@dataclass(frozen=True)
class CosignSignConfig:
    tpp_auth_url: str
    tpp_hsm_url: str
    tpp_username: str
    certificate_label: str

    tpp_password: str = None
    tpp_password_base64: str = None
    image: str = None

    extra_trusted_tls_ca_certs: str = None
    isolate_sessions: bool = True
    venafi_client_tools_dir: str = None

    @classmethod
    def from_env(cls):
        return cls(**utils.create_dataclass_inputs_from_env(config_schema))


class CosignSignCommand:
    def __init__(self, logger, config: CosignSignConfig):
        utils.check_one_of_two_config_options_set(
            'TPP_PASSWORD', config.tpp_password,
            'TPP_PASSWORD_BASE64', config.tpp_password_base64
        )

        self.logger = logger
        self.config = config

    def run(self):
        self._maybe_add_extra_trusted_tls_ca_certs()
        self._create_temp_dir()
        try:
            self._generate_session_id()
            self._login_tpp()
            self._invoke_cosign()
        finally:
            self._logout_tpp()
            self._delete_temp_dir()

    def _maybe_add_extra_trusted_tls_ca_certs(self):
        if self.config.extra_trusted_tls_ca_certs is not None:
            utils.add_ca_cert_to_truststore(self.logger, self.config.extra_trusted_tls_ca_certs)

    def _create_temp_dir(self):
        self.temp_dir = tempfile.TemporaryDirectory()

    def _delete_temp_dir(self):
        if hasattr(self, 'temp_dir'):
            self.temp_dir.cleanup()

    def _generate_session_id(self):
        if self.config.isolate_sessions:
            session_id = secrets.token_urlsafe(18)
            self.session_env = {'LIBHSMINSTANCE': session_id}
            self.logger.info(f'Session ID: {session_id}')
        else:
            self.session_env = {}

    def _create_pkcs11_uri_path(self) -> str:
        utils.get_pkcs11_uri_path(
            self.config.certificate_label,
            self.config.venafi_client_tools_dir)

    def _get_tpp_password(self) -> str:
        if self.config.tpp_password is not None:
            return self.config.tpp_password
        else:
            return str(base64.b64decode(self.config.tpp_password_base64), 'utf-8')

    def _login_tpp(self):
        utils.invoke_command(
            self.logger,
            'Logging into TPP: configuring client: requesting grant from server.',
            'Successfully obtained grant from TPP.',
            'Error requesting grant from TPP',
            'pkcs11config getgrant',
            print_output_on_success=False,
            command=[
                utils.get_pkcs11config_tool_path(
                    self.config.venafi_client_tools_dir),
                'getgrant',
                '--force',
                '--authurl=' + self.config.tpp_auth_url,
                '--hsmurl=' + self.config.tpp_hsm_url,
                '--username=' + self.config.tpp_username,
                '--password',
                self._get_tpp_password()
            ],
            masks=[
                False,
                False,
                False,
                False,
                False,
                False,
                False,
                True
            ],
            env=self.session_env
        )

    def _logout_tpp(self):
        try:
            utils.invoke_command(
                self.logger,
                'Logging out of TPP: revoking server grant.',
                'Successfully revoked server grant.',
                'Error revoking grant from TPP',
                'pkcs11config revokegrant',
                print_output_on_success=False,
                command=[
                    utils.get_pkcs11config_tool_path(
                        self.config.venafi_client_tools_dir),
                    'revokegrant',
                    '-force',
                    '-clear'
                ],
                env=self.session_env
            )
        except utils.AbortException:
            # utils.invoke_command() already logged an error message.
            pass
        except Exception:
            # Don't reraise exception: allow temp_dir to be cleaned up
            logging.exception('Unexpected exception during TPP logout')

    def _invoke_cosign(self):

        command = [
            'cosign',
            'sign',
            '--key',
            utils.get_pkcs11_uri_path(self.config.certificate_label, self.config.venafi_client_tools_dir)  # noqa:E501
        ]

        command.append(self.config.image)

        utils.invoke_command(
            self.logger,
            'Signing with cosign: %s' % (self.config.image,),
            "Successfully signed '%s'." % (self.config.image,),
            "Error signing '%s'" % (self.config.image,),
            'cosign',
            print_output_on_success=False,
            command=command,
            env=self.session_env
        )


def main():
    try:
        logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)-8s %(message)s')
        config = CosignSignConfig.from_env()
        command = CosignSignCommand(logging.getLogger(), config)
    except envparse.ConfigurationError as e:
        print(e, file=sys.stderr)
        sys.exit(1)
    try:
        command.run()
    except utils.AbortException:
        sys.exit(1)


if __name__ == '__main__':
    main()
