#!/usr/bin/env python
#
# Electrum - lightweight Bitcoin client
# Copyright (C) 2013 thomasv@gitorious
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.

import bitcoin
from bitcoin import *
from i18n import _
from transaction import Transaction, is_extended_pubkey
from util import print_msg, InvalidPassword


class Account(object):
    def __init__(self, v):
        self.receiving_pubkeys   = v.get('receiving', [])
        self.change_pubkeys      = v.get('change', [])
        # addresses will not be stored on disk
        self.receiving_addresses = map(self.pubkeys_to_address, self.receiving_pubkeys)
        self.change_addresses    = map(self.pubkeys_to_address, self.change_pubkeys)

    def dump(self):
        return {'receiving':self.receiving_pubkeys, 'change':self.change_pubkeys}

    def get_pubkey(self, for_change, n):
        pubkeys_list = self.change_pubkeys if for_change else self.receiving_pubkeys
        return pubkeys_list[n]

    def get_address(self, for_change, n):
        addr_list = self.change_addresses if for_change else self.receiving_addresses
        return addr_list[n]

    def get_pubkeys(self, for_change, n):
        return [ self.get_pubkey(for_change, n)]

    def get_addresses(self, for_change):
        addr_list = self.change_addresses if for_change else self.receiving_addresses
        return addr_list[:]

    def derive_pubkeys(self, for_change, n):
        pass

    def create_new_address(self, for_change):
        pubkeys_list = self.change_pubkeys if for_change else self.receiving_pubkeys
        addr_list = self.change_addresses if for_change else self.receiving_addresses
        n = len(pubkeys_list)
        pubkeys = self.derive_pubkeys(for_change, n)
        address = self.pubkeys_to_address(pubkeys)
        pubkeys_list.append(pubkeys)
        addr_list.append(address)
        print_msg(address)
        return address

    def pubkeys_to_address(self, pubkey):
        return public_key_to_bc_address(pubkey.decode('hex'))

    def has_change(self):
        return True

    def get_name(self, k):
        return _('Main account')

    def redeem_script(self, for_change, n):
        return None

    def synchronize_sequence(self, wallet, for_change):
        limit = wallet.gap_limit_for_change if for_change else wallet.gap_limit
        while True:
            addresses = self.get_addresses(for_change)
            if len(addresses) < limit:
                address = self.create_new_address(for_change)
                wallet.add_address(address)
                continue
            if map( lambda a: wallet.address_is_old(a), addresses[-limit:] ) == limit*[False]:
                break
            else:
                address = self.create_new_address(for_change)
                wallet.add_address(address)

    def synchronize(self, wallet):
        self.synchronize_sequence(wallet, False)
        self.synchronize_sequence(wallet, True)


class PendingAccount(Account):
    def __init__(self, v):
        self.pending_address = v['address']
        self.change_pubkeys = []
        self.receiving_pubkeys = [ v['pubkey'] ]

    def synchronize(self, wallet):
        return

    def get_addresses(self, is_change):
        return [] if is_change else [self.pending_address]

    def has_change(self):
        return False

    def dump(self):
        return {'pending':True, 'address':self.pending_address, 'pubkey':self.receiving_pubkeys[0] }

    def get_name(self, k):
        return _('Pending account')

    def get_master_pubkeys(self):
        return []

    def get_type(self):
        return _('pending')

    def get_xpubkeys(self, for_change, n):
        return self.get_pubkeys(for_change, n)

class P2SHAccount(object):

    def pubkeys_to_address(self, pubkeys, m, sort=True):
        pubkeys = sorted(pubkeys) if sort else pubkeys
        redeem_script = Transaction.multisig_script(pubkeys, m)
        address = hash_160_to_bc_address(hash_160(redeem_script.decode('hex')), 5)
        return address

    def redeem_script(self, pubkeys=None, m=None):
        pubkeys = self.xpubs if pubkeys is None else pubkeys
        m = self.m if m is None else m
        return Transaction.multisig_script(pubkeys, m)

    def get_address(self, pubkeys=None, m=None):
        pubkeys = self.xpubs if pubkeys is None else pubkeys
        m = self.m if m is None else m
        return self.pubkeys_to_address(pubkeys, m)


class ImportedAccount(Account, P2SHAccount):

    def __init__(self, d):
        self.keypairs = d.get('imported', {})
        self.p2sh_groups = d.get('imported_p2sh', {})

    def synchronize(self, wallet):
        return

    def pubkeys_to_address(self, pubkeys, m):
        try:
            return super(P2SHAccount, self).pubkeys_to_address(pubkeys, m, sort=False)
        except:
            return super(Account, self).pubkeys_to_address(pubkeys, m, sort=False)

    def get_addresses(self, for_change):
        return [] if for_change else sorted(
            self.keypairs.keys() +
            self.p2sh_groups.keys()
            # To compute these for verification, replace p2sh_groups.keys with:
            # [ pubkeys_to_address(
            #     [ xpub for xpub, xprv in record['keypairs'] ],
            #     record['m']) for record in self.p2sh_groups.values() ]
        )

    def get_pubkey(self, *sequence):
        for_change, i = sequence
        assert for_change == 0
        addr = self.get_addresses(0)[i]
        return self.keypairs[addr][0] if addr in keypairs else \
            [ k['xpub'] for k in self.p2sh_groups[addr]['keypairs'] ]

    def get_xpubkeys(self, for_change, n):
        return self.get_pubkeys(for_change, n)

    def get_private_keys(self, sequence, wallet, password):
        return self.get_private_key(sequence, wallet, password)

    def get_private_key(self, sequence, wallet, password):
        from wallet import pw_decode
        for_change, i = sequence
        assert for_change == 0
        address = self.get_addresses(0)[i]
        try:
            pk = pw_decode(self.keypairs[address][1], password)
            # this checks the password
            if address != address_from_private_key(pk):
                raise InvalidPassword()
            return [pk]
        except IndexError as e:
            pks = [ pw_decode(k[1]) for k in self.p2sh_groups(address)['keypairs'] ]
            return pks

    def has_change(self):
        return False

    def add(self, address, pubkey, privkey, password):
        from wallet import pw_encode
        self.keypairs[address] = ( pubkey, pw_encode(privkey, password) )

    def add_p2sh(self, m, keypairs, password, address=None):
        # keypairs should look like: [ (xpub,xpriv), ... ]
        from wallet import pw_encode
        calculated_address = self.pubkeys_to_address(
            pubkeys=[ kp[0].decode('hex') for kp in keypairs ], m=m)
        assert (calculated_address == address or address is None), "Specified address doesn't match calculated address."
        self.p2sh_groups[calculated_address] = {
            'keypairs': [ ( k[0], pw_encode(k[1], password) ) for k in keypairs ],
            'm': m
        }

    def remove(self, address):
        try:
            del self.keypairs[address]
        except:
            del self.p2sh_groups[address]

    def dump(self):
        return {'imported':self.keypairs}

    def get_name(self, k):
        return _('Imported keys')

    def update_password(self, old_password, new_password):
        def update_key_password(key, old, new):
            pw_encode(pw_decode(key, old), new)

        for k, v in self.keypairs.items():
            pubkey, a = v
            self.keypairs[k] = (
                pubkey, update_key_password(a, old_password, new_password))
        for k, v in self.p2sh_groups.items():
            for index, (pubkey, a) in enumerate(self.p2sh_groups[k]['keypairs']):
                self.p2sh_groups[k]['keypairs'][index] = (
                    pubkey, update_key_password(a, old_password, new_password))

class OldAccount(Account):
    """  Privatekey(type,n) = Master_private_key + H(n|S|type)  """

    def __init__(self, v):
        Account.__init__(self, v)
        self.mpk = v['mpk'].decode('hex')

    @classmethod
    def mpk_from_seed(klass, seed):
        curve = SECP256k1
        secexp = klass.stretch_key(seed)
        master_private_key = ecdsa.SigningKey.from_secret_exponent( secexp, curve = SECP256k1 )
        master_public_key = master_private_key.get_verifying_key().to_string().encode('hex')
        return master_public_key

    @classmethod
    def stretch_key(self,seed):
        oldseed = seed
        for i in range(100000):
            seed = hashlib.sha256(seed + oldseed).digest()
        return string_to_number( seed )

    @classmethod
    def get_sequence(self, mpk, for_change, n):
        return string_to_number( Hash( "%d:%d:"%(n,for_change) + mpk ) )

    def get_address(self, for_change, n):
        pubkey = self.get_pubkey(for_change, n)
        address = public_key_to_bc_address( pubkey.decode('hex') )
        return address

    @classmethod
    def get_pubkey_from_mpk(self, mpk, for_change, n):
        curve = SECP256k1
        z = self.get_sequence(mpk, for_change, n)
        master_public_key = ecdsa.VerifyingKey.from_string( mpk, curve = SECP256k1 )
        pubkey_point = master_public_key.pubkey.point + z*curve.generator
        public_key2 = ecdsa.VerifyingKey.from_public_point( pubkey_point, curve = SECP256k1 )
        return '04' + public_key2.to_string().encode('hex')

    def derive_pubkeys(self, for_change, n):
        return self.get_pubkey_from_mpk(self.mpk, for_change, n)

    def get_private_key_from_stretched_exponent(self, for_change, n, secexp):
        order = generator_secp256k1.order()
        secexp = ( secexp + self.get_sequence(self.mpk, for_change, n) ) % order
        pk = number_to_string( secexp, generator_secp256k1.order() )
        compressed = False
        return SecretToASecret( pk, compressed )


    def get_private_key(self, sequence, wallet, password):
        seed = wallet.get_seed(password)
        self.check_seed(seed)
        for_change, n = sequence
        secexp = self.stretch_key(seed)
        pk = self.get_private_key_from_stretched_exponent(for_change, n, secexp)
        return [pk]


    def check_seed(self, seed):
        curve = SECP256k1
        secexp = self.stretch_key(seed)
        master_private_key = ecdsa.SigningKey.from_secret_exponent( secexp, curve = SECP256k1 )
        master_public_key = master_private_key.get_verifying_key().to_string()
        if master_public_key != self.mpk:
            print_error('invalid password (mpk)', self.mpk.encode('hex'), master_public_key.encode('hex'))
            raise InvalidPassword()
        return True

    def get_master_pubkeys(self):
        return [self.mpk.encode('hex')]

    def get_type(self):
        return _('Old Electrum format')

    def get_xpubkeys(self, for_change, n):
        s = ''.join(map(lambda x: bitcoin.int_to_hex(x,2), (for_change, n)))
        mpk = self.mpk.encode('hex')
        x_pubkey = 'fe' + mpk + s
        return [ x_pubkey ]

    @classmethod
    def parse_xpubkey(self, x_pubkey):
        assert is_extended_pubkey(x_pubkey)
        pk = x_pubkey[2:]
        mpk = pk[0:128]
        dd = pk[128:]
        s = []
        while dd:
            n = int(bitcoin.rev_hex(dd[0:4]), 16)
            dd = dd[4:]
            s.append(n)
        assert len(s) == 2
        return mpk, s


class BIP32_Account(Account):

    def __init__(self, v):
        Account.__init__(self, v)
        self.xpub = v['xpub']
        self.xpub_receive = None
        self.xpub_change = None

    def dump(self):
        d = Account.dump(self)
        d['xpub'] = self.xpub
        return d

    def first_address(self):
        pubkeys = self.derive_pubkeys(0, 0)
        addr = self.pubkeys_to_address(pubkeys)
        return addr, pubkeys

    def get_master_pubkeys(self):
        return [self.xpub]

    @classmethod
    def derive_pubkey_from_xpub(self, xpub, for_change, n):
        _, _, _, c, cK = deserialize_xkey(xpub)
        for i in [for_change, n]:
            cK, c = CKD_pub(cK, c, i)
        return cK.encode('hex')

    def get_pubkey_from_xpub(self, xpub, for_change, n):
        xpubs = self.get_master_pubkeys()
        i = xpubs.index(xpub)
        pubkeys = self.get_pubkeys(for_change, n)
        return pubkeys[i]

    def derive_pubkeys(self, for_change, n):
        xpub = self.xpub_change if for_change else self.xpub_receive
        if xpub is None:
            xpub = bip32_public_derivation(self.xpub, "", "/%d"%for_change)
            if for_change:
                self.xpub_change = xpub
            else:
                self.xpub_receive = xpub
        _, _, _, c, cK = deserialize_xkey(xpub)
        cK, c = CKD_pub(cK, c, n)
        result = cK.encode('hex')
        return result


    def get_private_key(self, sequence, wallet, password):
        out = []
        xpubs = self.get_master_pubkeys()
        roots = [k for k, v in wallet.master_public_keys.iteritems() if v in xpubs]
        for root in roots:
            xpriv = wallet.get_master_private_key(root, password)
            if not xpriv:
                continue
            _, _, _, c, k = deserialize_xkey(xpriv)
            pk = bip32_private_key( sequence, k, c )
            out.append(pk)
        return out

    def get_type(self):
        return _('Standard 1 of 1')

    def get_xpubkeys(self, for_change, n):
        # unsorted
        s = ''.join(map(lambda x: bitcoin.int_to_hex(x,2), (for_change,n)))
        xpubs = self.get_master_pubkeys()
        return map(lambda xpub: 'ff' + bitcoin.DecodeBase58Check(xpub).encode('hex') + s, xpubs)

    @classmethod
    def parse_xpubkey(self, pubkey):
        assert is_extended_pubkey(pubkey)
        pk = pubkey.decode('hex')
        pk = pk[1:]
        xkey = bitcoin.EncodeBase58Check(pk[0:78])
        dd = pk[78:]
        s = []
        while dd:
            n = int( bitcoin.rev_hex(dd[0:2].encode('hex')), 16)
            dd = dd[2:]
            s.append(n)
        assert len(s) == 2
        return xkey, s

    def get_name(self, k):
        return "Main account" if k == '0' else "Account " + k


class BIP32_Account_2of2(BIP32_Account, P2SHAccount):

    def __init__(self, v):
        BIP32_Account.__init__(self, v)
        self.xpub2 = v['xpub2']
        self.m = 2

    def dump(self):
        d = BIP32_Account.dump(self)
        d['xpub2'] = self.xpub2
        return d

    def derive_pubkeys(self, for_change, n):
        return map(lambda x: self.derive_pubkey_from_xpub(x, for_change, n), self.get_master_pubkeys())

    def redeem_script(self, for_change, n):
        return super(P2SHAccount, self).redeem_script(
            self.derive_pubkeys(for_change, n))

    def pubkeys_to_address(self, pubkeys):
        return super(P2SHAccount, self).pubkeys_to_address(pubkeys)

    def get_address(self, for_change, n):
        return super(P2SHAccount, self).get_address(
            self.derive_pubkeys(for_change, n))

    def get_master_pubkeys(self):
        return [self.xpub, self.xpub2]

    def get_type(self):
        return _('Multisig 2 of 2')


class BIP32_Account_2of3(BIP32_Account_2of2):

    def __init__(self, v):
        BIP32_Account_2of2.__init__(self, v)
        self.xpub3 = v['xpub3']
        self.m = 3

    def dump(self):
        d = BIP32_Account_2of2.dump(self)
        d['xpub3'] = self.xpub3
        return d

    def get_master_pubkeys(self):
        return [self.xpub, self.xpub2, self.xpub3]

    def get_type(self):
        return _('Multisig 2 of 3')
