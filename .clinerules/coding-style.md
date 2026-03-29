## Brief overview
Global coding style rules to ensure proper code formatting and readability when writing JavaScript/Node.js files.

## Code formatting rules
- **Never write code in a single line** - Always use proper multi-line formatting with appropriate line breaks
- Use proper indentation (4 spaces consistently)
- Break long lines at logical points (parameters, conditions, etc.)
- Each statement should be on its own line
- Use blank lines to separate logical code blocks

## JavaScript/Bun.js specific
- Do not use fs module from node. Always use Bun's built in file I/O module
- For shell commands, import {$} from 'bun' and use await $ `someShellCommand`
- For sqlite, always use bun's built in sqlite db module.

## Common mistakes to avoid
- Do NOT collapse entire functions or classes into single lines
- Do NOT remove necessary whitespace for readability
- Do NOT combine multiple unrelated statements on one line