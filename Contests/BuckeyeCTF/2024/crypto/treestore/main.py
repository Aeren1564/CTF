from tree_store import TreeStore
from base64 import b64decode


def main():
    ts = TreeStore()

    with open("flag.bmp", "rb") as f:
        flag_bytes = f.read()
    ts.add_file(flag_bytes)
    print("[*] Added flag.bmp to the treestore")

    n_bytes = 0

    while True:
        print("[*] To add a file to the treestore, enter bytes base64 encoded")
        s = input(">>> ")
        if len(s) == 0:
            break

        file = b64decode(s)
        n_bytes += len(file)
        if n_bytes > 2 * 1024 * 1024:
            print("[-] Max storage exceeded!")
            break

        ts.add_file(file)

    print("[*] Bye!")


if __name__ == "__main__":
    main()
