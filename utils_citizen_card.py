# coding=utf-8
import PyKCS11
import OpenSSL
import os
import base64


class CitizenCardUtils:
    """Citizen Card Utils - Contains a list of functions to be used for citizen card management."""

    CERTIFICATES_FOLDER = "trusted_certificates"

    def __init__(self, debug=False):
        self.debug = debug
        self.PyKCS11 = PyKCS11.PyKCS11Lib()

    def _start_session(self, library="/usr/local/lib/libpteidpkcs11.so"):
        """Start session"""
        # load library
        self.PyKCS11.load(library)
        # get card from first slot
        try:
            card = self.PyKCS11.getSlotList()[0]
        except Exception as exception:
            if self.debug:
                print "No cards in slots\nException: " + str(exception)
            else:
                print "No cards in slots"
            return None
        # start session from card
        try:
            card_session = self.PyKCS11.openSession(card)
        except Exception as exception:
            if self.debug:
                print "Couldn't start card session\nException: " + str(exception)
            else:
                print "Couldn't start card session"
            return None
        return card_session

    def get_citizen_certificates(self, library="/usr/local/lib/libpteidpkcs11.so"):
        """Returns citizen list of certificates in the form of {TYPE, CERTIFICATE_PEM} or an empty list if failed"""
        # init certificates as a list
        certificates = []
        # start session
        card_session = self._start_session(library)
        if not isinstance(card_session, PyKCS11.Session):
            return certificates
        # retrieve certificates
        try:
            # cycles trough card objects
            for entry in card_session.findObjects([(PyKCS11.CKA_CLASS, PyKCS11.CKO_CERTIFICATE)]):
                # convert entry to dictionary
                dict_entry = entry.to_dict()
                # get certificate
                cert = OpenSSL.crypto.load_certificate(type=OpenSSL.crypto.FILETYPE_ASN1,
                                                       buffer=''.join(chr(c) for c in dict_entry['CKA_VALUE']))
                # build certificate
                certificate = {
                    'TYPE': dict_entry['CKA_LABEL'],
                    'CERTIFICATE_PEM': OpenSSL.crypto.dump_certificate(type=OpenSSL.crypto.FILETYPE_PEM, cert=cert),
                }
                # add to certificate list
                certificates.append(certificate)
        except Exception as exception:
            if self.debug:
                print "Couldn't retrieve certificates\nException: " + str(exception)
            else:
                print "Couldn't retrieve certificates"
        finally:
            card_session.closeSession()
        # returns None or found certificates
        return certificates

    def sign(self, text, key_type, library="/usr/local/lib/libpteidpkcs11.so"):
        """Signs the given text with the users CITIZEN SIGNATURE KEY or CITIZEN AUTHENTICATION KEY, depending on type
        being SIGNATURE OR AUTHENTICATION, result is encoded in base 64"""
        # init signature
        signature = ''
        # start session
        card_session = self._start_session(library)
        if not card_session:
            return signature
        # retrieve certificates
        try:
            if key_type in {'AUTHENTICATION'}:
                private_key = card_session.findObjects(template=((PyKCS11.CKA_LABEL, "CITIZEN AUTHENTICATION KEY"),
                                                                 (PyKCS11.CKA_CLASS, PyKCS11.CKO_PRIVATE_KEY),
                                                                 (PyKCS11.CKA_KEY_TYPE, PyKCS11.CKK_RSA)))[0]
            elif key_type in {'SIGNATURE'}:
                private_key = card_session.findObjects(template=((PyKCS11.CKA_LABEL, "CITIZEN SIGNATURE KEY"),
                                                                 (PyKCS11.CKA_CLASS, PyKCS11.CKO_PRIVATE_KEY),
                                                                 (PyKCS11.CKA_KEY_TYPE, PyKCS11.CKK_RSA)))[0]
            else:
                return signature
            # if instance of unicode encode
            if isinstance(text, unicode):
                text = text.encode('utf-8')
            # encode text to base 64 for text type
            base64_text = base64.b64encode(text)
            # sign
            sign_tuple = card_session.sign(private_key, base64_text, PyKCS11.Mechanism(PyKCS11.CKM_SHA256_RSA_PKCS, ""))
            # convert to single string
            sign_text = ''.join(chr(c) for c in sign_tuple)
            # encode in base64
            signature = base64.b64encode(sign_text)
        except Exception as exception:
            if self.debug:
                print "Sign text\nException: " + str(exception)
            else:
                print "Sign text"
        finally:
            card_session.closeSession()
        # returns None or found certificates
        return signature

    @staticmethod
    def get_certificate_subject_info(certificate_pem):
        """Returns the citizen information in the form of {CC_NUMBER, COMPLETE_NAME} if Citizen certificate,
         {COMPLETE_NAME} if SUB or ROOT or {} if neither of those"""
        certificate = OpenSSL.crypto.load_certificate(type=OpenSSL.crypto.FILETYPE_PEM, buffer=certificate_pem)
        subject_info = certificate.get_subject().get_components()
        if len(subject_info) == 8:
            return {u'cc_number': subject_info[6][1], u'complete_name': subject_info[7][1].decode('utf-8')}
        if len(subject_info) == 4:
            return {u'complete_name': subject_info[3][1].decode('utf-8')}
        return {}

    @staticmethod
    def get_public_key(certificate_pem):
        """Get public key form certificate"""
        # load certificate
        certificate = OpenSSL.crypto.load_certificate(type=OpenSSL.crypto.FILETYPE_PEM, buffer=certificate_pem)
        # get key
        return OpenSSL.crypto.dump_publickey(type=OpenSSL.crypto.FILETYPE_PEM, pkey=certificate.get_pubkey())

    @staticmethod
    def verify_signature(certificate_pem, signature, text, digest=b'SHA256'):
        """Verifies signature, signature should come in base 64 encoding"""
        # load certificate
        certificate = OpenSSL.crypto.load_certificate(type=OpenSSL.crypto.FILETYPE_PEM, buffer=certificate_pem)
        # if instance of unicode encode
        if isinstance(text, unicode):
            text = text.encode('utf-8')
        # encode text to base 64 for encoding reasons
        base64_text = base64.b64encode(text)
        # decode signature
        sign_text = base64.b64decode(signature)
        # verify text
        try:
            OpenSSL.crypto.verify(cert=certificate, signature=sign_text, data=base64_text, digest=digest)
            return True
        except OpenSSL.crypto.Error:
            return False

    @staticmethod
    def verify_certificate_chain(certificate_pem):
        """Verifies certificate trust chain"""
        # store
        store = OpenSSL.crypto.X509Store()
        # add known certificates
        if not os.path.exists(CitizenCardUtils.CERTIFICATES_FOLDER):
            return False
        for file_name in os.listdir(CitizenCardUtils.CERTIFICATES_FOLDER):
            if file_name in {'Makefile'}:
                continue
            try:
                with open(os.path.join(CitizenCardUtils.CERTIFICATES_FOLDER, file_name), 'r') as crl:
                    store.add_cert(cert=OpenSSL.crypto.load_certificate(type=OpenSSL.crypto.FILETYPE_ASN1, buffer=crl.read()))
            except OpenSSL.crypto.Error:
                with open(os.path.join(CitizenCardUtils.CERTIFICATES_FOLDER, file_name), 'r') as crl:
                    store.add_cert(cert=OpenSSL.crypto.load_certificate(type=OpenSSL.crypto.FILETYPE_PEM, buffer=crl.read()))
        # load certificate
        certificate = OpenSSL.crypto.load_certificate(type=OpenSSL.crypto.FILETYPE_PEM, buffer=certificate_pem)
        # verify certificate
        try:
            OpenSSL.crypto.X509StoreContext(store=store, certificate=certificate).verify_certificate()
            return True
        except OpenSSL.crypto.X509StoreContextError:
            return False
