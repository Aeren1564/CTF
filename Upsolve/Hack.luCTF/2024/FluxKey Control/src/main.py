import rooms.locker
import rooms.gym
import crypto

from const import MASTER_KEY

hsh = crypto.Keccak()
hsh.absorb(MASTER_KEY + b"locker room")
KEYCARD = hsh.squeeze()

ROOMS = {
    "locker room": rooms.locker.locker_zone,
    "gym": rooms.gym.gym_zone,
}

def main():
    print("Welcome to the rooms of FluxSports!!!")
    print()
    print(f"You find the following keycard on the floor:", KEYCARD.hex())
    print()
    while True:
        inpt = None
        while inpt is None:
            print("There are doors to the following rooms:")
            for i, name in enumerate(ROOMS.keys()):
                print(f"{i}: {name}")
            print()
            try:
                inpt = int(input(f"Enter room number (0-{len(ROOMS)-1}): "))
                if not (0 <= inpt < len(ROOMS)):
                    print(f"no room with number {inpt}" + "\n"*3)
                    continue
            except ValueError:
                print("invalid room number" + "\n"*3)
                continue

        room_name, enter_room = list(ROOMS.items())[inpt]
        hsh = crypto.Keccak()
        hsh.absorb(MASTER_KEY + room_name.encode())
        valid_key = hsh.squeeze()
        print("The door is locked.")

        passkey = input("Enter keycode to unlock: ")
        if passkey != valid_key.hex():
            print("The passkey was rejected!" + "\n" * 3)
        else:
            print(f"The door opens and you enter the {room_name}.")
            print()
            enter_room()

if __name__ == '__main__':
    main()
