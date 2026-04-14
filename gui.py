import curses
import sys
import os
import io
import time
from contextlib import redirect_stdout

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from main import main as cli_main
from zenith.engine import ZenithEngine


class DummyArgs:
    def __init__(self, command, risk_threshold=0, json=False, profile="config.yaml"):
        self.command = command
        self.risk_threshold = risk_threshold
        self.json = json
        self.profile = os.path.join(os.path.dirname(os.path.abspath(__file__)), profile)

def draw_header(stdscr):
    logo = """
           ░░░░░░░░░░░░░                                                                            
         ▒▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓░                                                                          
       ░▓████████████████▓▒                                                                         
     ░▒▓███████████████████▓▒      ░░░░░░░░░                          ░▒▒░         ▒▓▓▒             
    ▒▓███████████████████████▓░   ▓████▓▓▓▓▓▒                         ▓██▒   ░▒░   ▓██▓             
   ░▓████████▓▓▓▓▓▓▓▓█████████▒   ▒▒▒▒▒▓▓███▒                         ░▒▒░  ▒██▓   ▓██▓             
   ░▓███████▓░  ░░  ░▓▓███████▒        ▒▓██▒    ░▒▒▒▒░    ░░░  ░▒▒░   ░▒▒░ ░▓██▓▒░ ▓██▓ ░▒▒▒        
   ░▓██████▓  ▒▓▓▓▓▒  ▒███████▒       ░▓██▓    ▒▓█▓▓█▓▒  ▒██▓▒▓███▓▒  ▓██▒░▓█████▒ ▓██▓▓▓███▓       
   ░▓██████▓ ░██████▒ ▒███████▒      ░▓██▓    ▒██▓░ ▓█▓░ ░███▓░░▓██▓  ▓██▒ ░▓██▓░  ▓██▓▒░▒███░      
   ░▓██████▓ ▒██████▒ ▒███████▒     ░▓██▓░    ▓██▒  ▒██▒ ░███░  ▓██▓  ▓██▒  ▓██▓   ▓██▓  ░▓██░      
   ░▓██████▓  ▓▓███▓░ ▒███████▒    ░▓██▓░     ▓██▓▓▓▓██▒ ░███░  ▓██▓  ▓██▒  ▓██▓   ▓██▓  ░▓██░      
   ░▓██████▓▓░ ░░░░  ▒▓███████▒    ▓██▓░      ▓██▓▒▒▒░░░ ░███░  ▓██▓  ▓██▒  ▓██▓   ▓██▓  ░▓██░      
   ░▓████████▓▒▒▒▒▒▒▓█████████▒   ▓███▓░░░░░░ ▒██▓░  ░░  ░███░  ▓██▓  ▓██▒  ▓██▓   ▓██▓  ░▓██░      
    ▒▓███████████████████████▓░  ░██████████▓  ▓██▓▓▓▓▓░ ░███░  ▓██▓  ▓██▒  ▒███▓▒ ▓██▓  ░███░      
     ░▓████████████████████▓▒     ▒▒▒▒▒▒▒▒▒▒▒   ░▒▒▓▒▒░   ▒▒▒   ░▒▒░  ▒▒▒░   ▒▒▓▒░ ░▒▒░   ▒▒▒░      
       ▒▓████████████████▓▓░                                                    ░░       ░          
        ░▒▓█████████████▓░        ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░▒▒░░░▒░░░   ░▒░▒▒▒▒▒▒▒▒▒▒▒      
          ░░░░░░░░░░░░░░          ░░▒▒▒▒▒▒▒░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░   ░▒░▒▒░░▒░▒▒ ░▒      
    """
    stdscr.attron(curses.color_pair(1) | curses.A_BOLD)
    for i, line in enumerate(logo.split("\n")):
        try:
            stdscr.addstr(i, 2, line)
        except curses.error:
            pass 
    stdscr.attroff(curses.color_pair(1) | curses.A_BOLD)
    return len(logo.split("\n")) + 1

def confirm_prompt(stdscr, y, x, action_name):
    prompt_str = f"Are you sure you want to run {action_name}? [Y/n]: "
    stdscr.addstr(y, x, prompt_str, curses.color_pair(3))
    stdscr.refresh()
    curses.echo()
    try:
        response = stdscr.getstr(y, x + len(prompt_str), 10).decode('utf-8').strip().lower()
    except Exception:
        response = ""
    curses.noecho()
    return response in ['y', 'yes', '']

def run_scan(stdscr, scan_type):
    stdscr.clear()
    stdscr.addstr(2, 2, f"Running {scan_type} Scan...", curses.color_pair(2) | curses.A_BOLD)
    stdscr.addstr(4, 2, "Please wait, gathering telemetry...", curses.color_pair(3))
    stdscr.refresh()

    engine = ZenithEngine(DummyArgs(scan_type))
    
 
    f = io.StringIO()
    with redirect_stdout(f):
        engine.run_scan()
    
    output = f.getvalue()

    stdscr.clear()
    stdscr.addstr(1, 2, f"=== RESULTS: {scan_type} ===", curses.color_pair(2) | curses.A_BOLD)
    
    lines = output.strip().split("\n")
    max_y, max_x = stdscr.getmaxyx()
    
    for i, line in enumerate(lines):
        if 3 + i < max_y - 2:
            try:
            
                if "Score:" in line:
                    stdscr.addstr(3 + i, 2, line, curses.color_pair(1))
                else:
                    stdscr.addstr(3 + i, 2, line[:max_x-4])
            except curses.error:
                pass
        else:
            stdscr.addstr(max_y - 3, 2, "...(output truncated)...", curses.color_pair(3))
            break
            
    stdscr.addstr(max_y - 1, 2, "Press any key to return to the menu...", curses.color_pair(4) | curses.A_BLINK)
    stdscr.refresh()
    stdscr.getch()

def main(stdscr):

    curses.curs_set(0) 
    curses.start_color()
    curses.init_pair(1, curses.COLOR_CYAN, curses.COLOR_BLACK)
    curses.init_pair(2, curses.COLOR_GREEN, curses.COLOR_BLACK)
    curses.init_pair(3, curses.COLOR_YELLOW, curses.COLOR_BLACK)
    curses.init_pair(4, curses.COLOR_WHITE, curses.COLOR_BLACK)

    curses.init_pair(10, curses.COLOR_BLACK, curses.COLOR_CYAN) 

    options = [
        ("Full System Scan", "full-scan"),
        ("Process Analysis", "process"),
        ("Network Analysis", "network"),
        ("Persistence Discovery", "persistence"),
        ("Exit", "exit")
    ]
    current_row = 0

    while True:
        stdscr.clear()
        menu_y = draw_header(stdscr)

        stdscr.addstr(menu_y, 4, "Select an operation (Up/Down Arrows, Enter to select):", curses.color_pair(4))
        menu_y += 2

        for i, (display_text, _) in enumerate(options):
            x = 6
            y = menu_y + i
            if i == current_row:
                stdscr.attron(curses.color_pair(10))
                stdscr.addstr(y, x, f" > {display_text} < ")
                stdscr.attroff(curses.color_pair(10))
            else:
                stdscr.addstr(y, x, f"   {display_text}   ")

        stdscr.refresh()
        key = stdscr.getch()

        if key == curses.KEY_UP and current_row > 0:
            current_row -= 1
        elif key == curses.KEY_DOWN and current_row < len(options) - 1:
            current_row += 1
        elif key == curses.KEY_ENTER or key in [10, 13]:
       
            selected_display, selected_cmd = options[current_row]
            
            if selected_cmd == "exit":
                break
            
          
            prompt_y = menu_y + len(options) + 2
            if confirm_prompt(stdscr, prompt_y, 4, selected_display):
                run_scan(stdscr, selected_cmd)

if __name__ == "__main__":
    try:
        curses.wrapper(main)
    except KeyboardInterrupt:
        pass
    except Exception as e:
        print(f"Error starting TUI: {e}")
