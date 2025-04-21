from pss import PssKey, generate_share, provision, verify_id

try:
    with open('./flag.txt', 'r') as f:
        flag = f.read()
except:
    flag = 'bctf{REDACTED}'

FLAG_SHARE_ID = 1337
FORBIDDEN_SHARE_ID = 20984567098134765

def get_share_id():
    print('Enter share id:')
    share_id = int(input('>> ').strip())
    verify_id(share_id)
    return share_id

def main():
    share_count = 5
    key = PssKey.generate(share_count)

    flag_share = generate_share(key, FLAG_SHARE_ID, flag.encode())
    print('Here is your share of the flag :)')
    print(flag_share.to_json())

    while True:
        print()
        print('Options:')
        print('1: generate share')
        print('2: provision shares')
        choice = input('>> ').strip()

        if choice == '1':
            share_id = get_share_id()
            if share_id == FORBIDDEN_SHARE_ID or share_id == FLAG_SHARE_ID:
                print('Nice try :P')
                return

            share = generate_share(key, share_id, b'no secret here...')
            print('Here is your share:')
            print(share.to_json())

        elif choice == '2':
            share_ids = [get_share_id() for _ in range(share_count)]

            if FLAG_SHARE_ID in share_ids and FORBIDDEN_SHARE_ID not in share_ids:
                print('Nice try :P')
                return

            provision_data = provision(key.provision_key, share_ids)
            print('Here is the provisioning data:')
            print(provision_data.to_json())
        else:
            print('Invalid choice')
            return

if __name__ == '__main__':
    main()
