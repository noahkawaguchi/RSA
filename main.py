import menu_options as menu
from print_only import welcome, main_menu

def main():
    width = 25
    welcome(width) 
    # Initialize all integer menu option arguments to 0 and the list 
    # menu option argument to [] in case the user does not use the 
    # program in order.
    p, q, n, e, d = 0, 0, 0, 0, 0 
    C = []
    # Ensure the menu will display before there is any user input.
    direction = 'menu'
    while True:
        # If the user chooses to move directly from one step to the 
        # next, take them there directly without unnecessarily 
        # presenting them with the main menu in between.
        if direction == 'menu':
            main_menu(width)
            menu_choice = input('Enter the number of your choice: ')
        else:
            menu_choice = direction

        # Pass and return the RSA variables so the user does not have to 
        # manually type them in if they do the steps in order.
        # Use the direction variable to allow the user to navigate from 
        # within menu options without having to return to the main menu 
        # every time.
        if menu_choice == '1':
            p, q, direction = menu.generate_primes_option()
        elif menu_choice == '2':
            (n, e), (n, d), direction = menu.generate_keys_option(p, q)
        elif menu_choice == '3':
            C, direction = menu.encode_option(n, e)
        elif menu_choice == '4':
            direction = menu.decode_option(n, d, C)
        elif menu_choice == '5':
            direction = menu.break_codes_option(n, e, C)
        elif menu_choice == '0':
            print()
            print('Goodbye for now!')
            print()
            break
        else:
            print('Invalid response, please select one of the options')

if __name__ == "__main__":
    main()
