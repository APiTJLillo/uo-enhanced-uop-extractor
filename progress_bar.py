import sys
import math
import shutil
from typing import TextIO

class ProgressBar:
    def __init__(self, target: TextIO = sys.stdout):
        self._target = target
        self._text_only = not self._target.isatty()
        self._update_width()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if exc_type is None:
            self.update(1.0)
        if not self._text_only:
            self._target.write('\n')
        self._target.flush()

    def _update_width(self):
        self._width, _ = shutil.get_terminal_size((80, 20))

    def update(self, progress: float):
        self._update_width()
        if self._width < 12:
            percent_str = ''
            progress_bar_str = self.progress_bar_str(progress, self._width - 2)
        elif self._width < 40:
            percent_str = "{:6.2f} %".format(progress * 100)
            progress_bar_str = self.progress_bar_str(progress, self._width - 11) + ' '
        else:
            percent_str = "{:6.2f} %".format(progress * 100) + "  "
            progress_bar_str = " " * 5 + self.progress_bar_str(progress, self._width - 21)
        
        if self._text_only:
            self._target.write(progress_bar_str + percent_str + '\n')
        else:
            self._target.write('\033[G' + progress_bar_str + percent_str)
        self._target.flush()

    @staticmethod
    def progress_bar_str(progress: float, width: int) -> str:
        """Generate the progress bar string with the given progress and width."""
        progress = min(1, max(0, progress))
        whole_width = math.floor(progress * width)
        remainder_width = (progress * width) % 1
        part_width = math.floor(remainder_width * 8)
        part_char = [" ", "▏", "▎", "▍", "▌", "▋", "▊", "▉"][part_width]
        if (width - whole_width - 1) < 0:
            part_char = ""
        line = "[" + "█" * whole_width + part_char + " " * (width - whole_width - 1) + "]"
        return line
