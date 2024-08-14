from ast import literal_eval

def validate_pos_int(prompt: str) -> int:
    """Prompt the user until they enter a positive integer.
    Return the integer.
    """
    while True:
        try:
            myint = int(input(prompt))
            if myint > 0:
                return myint
            else:
                print('Invalid input, please enter a positive number')
        except ValueError:
            print('Invalid input, please enter an integer')

def validate_list(prompt: str) -> list:
    """Prompt the user until they enter a list.
    Return the list.
    """
    while True:
        user_input = input(prompt)
        try:
            mylist = literal_eval(user_input)
            if isinstance(mylist, list):
                return mylist
            else:
                print('Invalid input, please enter a list')
        except (ValueError, SyntaxError):
            print('Invalid input, please enter a list')
