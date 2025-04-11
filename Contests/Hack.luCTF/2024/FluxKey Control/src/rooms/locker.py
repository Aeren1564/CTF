import crypto

from const import MASTER_KEY

LOCKER_COUNT = 321

def print_board(board):
    for row in [board[i * 3:(i + 1) * 3] for i in range(3)]:
        print('| ' + ' | '.join(row) + ' |')

def available_moves(board):
    return [i for i, spot in enumerate(board) if spot == ' ']

def make_move(board, square, letter):
    if board[square] == ' ':
        board[square] = letter
        return True
    return False

def check_winner(board, square, letter):
    row_ind = square // 3
    row = board[row_ind * 3:(row_ind + 1) * 3]
    if all([spot == letter for spot in row]):
        return True

    col_ind = square % 3
    column = [board[col_ind + i * 3] for i in range(3)]
    if all([spot == letter for spot in column]):
        return True

    if square % 2 == 0:
        diagonal1 = [board[i] for i in [0, 4, 8]]
        if all([spot == letter for spot in diagonal1]):
            return True
        diagonal2 = [board[i] for i in [2, 4, 6]]
        if all([spot == letter for spot in diagonal2]):
            return True

    return False

def bot_move(board, rng):
    available = available_moves(board)
    if len(available) > 0:
        bot_choice = rng.getbits(16) % len(available)
        return available[bot_choice]
    return None

def player_move(board):
    available = available_moves(board)
    move = None
    while move not in available:
        try:
            move = int(input(f"Select a move (0-8): "))
            if move not in available:
                print("Invalid move. Try again.")
        except ValueError:
            print("Please input a number between 0 and 8.")
    return move

def play_game(rng):
    board = [' ' for _ in range(9)]
    current_winner = None

    print_board(board)

    letter = 'X'
    while True:
        if letter == 'X':
            print("Your turn.")
            move = player_move(board)
        else:
            print("Bot's turn.")
            move = bot_move(board, rng)

        if make_move(board, move, letter):
            print(f"{letter} makes a move to square {move}")
            print_board(board)

            if check_winner(board, move, letter):
                return letter

            letter = 'O' if letter == 'X' else 'X'

        if not available_moves(board):
            return 'Tie'

def locker_zone():
    hsh = crypto.Keccak()
    hsh.absorb(MASTER_KEY + b"locker room")
    rng = hsh.get_rng()
    print("Hey welcome to the Locker Room i cant remember what Locker i had or the Passcode for it can you help me find it")
    for locker_number in range(1, LOCKER_COUNT + 1):  
        print(f"\nLocker Number {locker_number}...\n")
        winner = play_game(rng)

        if locker_number == LOCKER_COUNT: 
            if winner == 'O':
                print("That doesnt seem like the correct Passcode!")
                exit(0)
            elif winner == 'X':  
                print(f"Hey great you guessed correct!")
                print(f"\nThat looks like you found the correct one!")
                print(f"\nThe Locker is empty")
            else:  
                print(f"The display froze")

        elif winner == 'O':
            print("That doesnt seem like the correct Passcode!")
            exit(0)
        elif winner == 'X':  
            print(f"Hey great you guessed correct! Seems like this Locker is empty.")
        else:  
            print(f"The display froze, let's continue with the next locker...")




