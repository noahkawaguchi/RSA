from typing import Tuple

from input_validation import validate_pos_int, validate_list


def old_or_new_ints(
        val_names: Tuple[str, str], 
        old_values: Tuple[int, int]) -> Tuple[int, int]:
    """Arguments for val_names (strings) and old_values (integers) must
    be tuples of the same length and order.
    Prompt the user to use the preexisting values or input new ones.
    Return the appropriate values as a tuple.
    """

    # It is only necessary to ask the user if they want to use the
    # previous values if there are previous values available.
    valid_values = True
    for val in old_values:
        if val <= 0:
            valid_values = False
            break
    
    # If the user just generated values in previous steps, ask if they
    # want to use them or not.
    if valid_values:
        val_names_str = ''.join(''.join(str(val_names).split("'")).split('"'))
        print((f'You previously generated the values {old_values} for '
               f'{val_names_str}. Would you like to use these values or '
               'enter new ones?'))
        while True:
            user_response = input(('Enter 1 to use the old values, '
                                   '2 to enter new ones: '))
            if user_response == '1':
                return old_values
            elif user_response == '2':
                need_new = True
                break
            else:
                print('Invalid response, please select one of the options')
    else:
        need_new = True

    # If the user rejects the previous values or there are not any,
    # collect and return new ones.
    if need_new:
        new_val_list = []
        for val_name in val_names:
            new_val = validate_pos_int(f'Enter your value for {val_name}: ')
            new_val_list.append(new_val)
        new_val_tuple = tuple(new_val_list)
        return new_val_tuple

def old_or_new_list(list_name: str, old_list: list) -> list:
    """Prompt the user to use the preexisting list or input a new one.
    Return the appropriate list accordingly.
    """

    # It is only necessary to ask the user if they want to use the
    # previous list if there is a previous list available.
    if len(old_list) > 0:
        valid_values = True
    else:
        valid_values = False

    # If the user just generated a list in previous steps, ask if they
    # want to use it or not.
    if valid_values:
        print()
        print((f'You previously generated the list {old_list} for '
               f'{list_name}. Would you like to use this list or enter a new '
               'one?'))
        print()
        while True:
            user_response = input(('Enter 1 to use the old list, 2 to enter a '
                                   'new one: '))
            if user_response == '1':
                return old_list
            elif user_response == '2':
                need_new = True
                break
            else:
                print('Invalid response, please select one of the options')
    else:
        need_new = True

    # If the user rejects the previous list or there are is not one,
    # collect and return a new one.
    if need_new:
        print(('Enter a list of integers separated with commas and surrounded '
               'by brackets. Example: [321, 654, 987]'))
        new_list = validate_list(f'Enter your list for {list_name}: ')
        return new_list

def what_next(next_step: str) -> str:
    """Argument should be a numeral as a one-character string
    corresponding to the next step (the next menu option).
    For example: '3'.
    If this is the last step, pass the string 'no more'.
    Prompt the user to return to the main menu, continue to the next
    step, or quit the program.
    Return a string corresponding to the user's choice.
    """

    # Check whether there are more steps to go to after this.
    if next_step == 'no more':
        more_steps = False
    else:
        more_steps = True

    # Get and return the user's choice of main menu, next step, or quit.
    print()
    print('What would you like to do next?')
    while True:
        print()
        print('1 - Return to the main menu')
        if more_steps:
            print('2 - Continue to the next step')
        print('0 - Quit')
        user_choice = input('Enter the number of your choice: ')
        if user_choice == '1':
            direction = 'menu'
            break
        elif user_choice == '2' and more_steps:
            direction = next_step
            break
        elif user_choice == '0':
            direction = '0'
            break
        else:
            print('Invalid response, please select one of the options')
    return direction
