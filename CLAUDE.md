# CLAUDE.md

## Core Directives

The implementation_plan.md is the document of most importance. It is not to be changed except to mark a step complete. It defines this project and what is to be done. Follow it until it is completed.

**CORRECTNESS FIRST**: Every solution must be production-ready, functionally complete, and architecturally sound. No shortcuts, no placeholders, no "TODO" comments.

**CONCISE SOLUTIONS**: Write minimal, essential code. Eliminate redundancy, verbose comments, and unnecessary abstractions. Prefer clarity through simplicity.

**NO MOCKS**: Use real implementations, actual databases, genuine APIs, and authentic integrations. Build working systems that function end-to-end.

## Response Requirements

### Code Quality Standards
- All code must compile/run without errors
- Include proper error handling and edge cases
- Use appropriate data structures and algorithms
- Follow language-specific best practices and idioms
- Implement proper resource management (connections, files, memory)

### Project Structure
- Create complete, deployable applications
- Include all necessary configuration files
- Provide clear dependency management
- Structure code for maintainability and scalability
- Include environment setup and deployment instructions

### Implementation Approach
- Use real databases (SQLite for local, PostgreSQL/MySQL for production)
- Implement actual API calls and external service integrations
- Create functional user interfaces with proper state management
- Build genuine authentication and authorization systems
- Include real logging, monitoring, and error tracking

## Prohibited Approaches
- Mock objects, stub functions, or fake implementations
- Placeholder text like "// TODO: implement this"
- Incomplete error handling or edge case coverage
- Over-engineered solutions with unnecessary complexity
- Verbose documentation that doesn't add value

## Expected Deliverables
- Fully functional codebase ready for immediate deployment
- Complete test suites that verify actual functionality
- Production-ready configuration and deployment scripts
- Minimal but sufficient documentation focused on setup and usage
- Clear instructions for running, testing, and maintaining the system

## Communication Style
- Provide direct, actionable solutions
- Skip explanatory preambles unless specifically requested
- Focus on implementation details that matter
- Highlight critical decisions and trade-offs
- Assume technical competence in the reader
