def welcome(welcome_width: int) -> None:
    """Print the welcome message and introduce the program using the
    provided width.
    """
    print()
    print('*' * welcome_width)
    print('WELCOME TO'.center(welcome_width))
    print("NOAH KAWAGUCHI'S".center(welcome_width))
    print('RSA PROGRAM'.center(welcome_width))
    print('(summer 2024)'.center(welcome_width))
    print('*' * welcome_width)
    print()
    print(('This is a simple program that guides the user through the '
          'steps of RSA public key encryption as listed in the main menu '
          'below. To best experience the full program, it is recommended '
          'to go through the menu options in order. You can move directly '
          'from one to the next without having to return to the main menu, '
          'and you can use the values generated in previous steps without '
          'having to type them in manually! However, you can also use each '
          'menu option independently if you already have elements of RSA '
          'generated previously and/or through other means. Happy '
          'encrypting!'))

def main_menu(main_menu_width: int) -> None:
    """Print the main menu using the provided width."""
    print()
    print('-' * main_menu_width)
    print('Main Menu'.center(main_menu_width))
    print('-' * main_menu_width)
    print('1 - Generate Primes')
    print('2 - Generate Keys')
    print('3 - Encode')
    print('4 - Decode')
    print('5 - Break Codes')
    print('0 - Quit')
    print()
