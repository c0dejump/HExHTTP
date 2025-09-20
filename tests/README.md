# HExHTTP Test Suite

This directory contains the comprehensive test suite for HExHTTP, designed to ensure no regressions are introduced when making changes to the codebase.

## Overview

The test suite consists of:

- **Mock Server**: A Flask-based server that simulates various web technologies and vulnerabilities
- **Regression Tests**: Comprehensive tests covering core functionality
- **Test Fixtures**: Predefined test data and configurations
- **Automated Testing**: CI/CD ready test automation

## Test Structure

```
tests/
├── __init__.py              # Test package
├── conftest.py              # Pytest configuration & fixtures
├── mock_server.py           # Flask mock server
├── test_regression.py       # Main regression tests
├── pytest.ini              # Pytest configuration
├── fixtures/
│   └── test_urls.txt       # Test URL list
└── README.md               # This file
```

## Test Categories

### Priority 1 Tests (Critical)
- CLI help and basic functionality
- Technology detection (Apache, Nginx, Cloudflare)
- Basic URL processing
- False positive prevention

### Priority 2 Tests (Important)
- File input processing
- Threading stability
- Header analysis
- Cache file detection
- Error handling

### Priority 3 Tests (Advanced)
- Custom headers
- Verbose output
- HHO vulnerability detection
- Advanced features

### Integration Tests
- Complete scan workflows
- Multi-URL processing
- End-to-end functionality

## Mock Server Endpoints

The mock server provides controlled test scenarios:

| Endpoint | Purpose |
|----------|---------|
| `/apache/` | Apache server simulation |
| `/nginx/` | Nginx server simulation |
| `/cloudflare/` | Cloudflare protected site |
| `/vulnerable/hho` | HHO cache poisoning vulnerability |
| `/safe/` | Safe endpoint (no vulnerabilities) |
| `/cache/static.css` | Cacheable CSS resource |
| `/cache/script.js` | Cacheable JavaScript resource |
| `/headers/uncommon` | Uncommon headers testing |
| `/errors/500` | Server error simulation |
| `/health` | Health check endpoint |

## Running Tests

### Prerequisites

Install test dependencies:
```bash
pip install -e .[test]
# or
pip install -e .[dev]
```

### Basic Test Execution

Run all tests:
```bash
pytest tests/
```

Run with verbose output:
```bash
pytest tests/ -v
```

**Quick Regression Testing** (recommended for development):
```bash
pytest tests/ -c tests/pytest-quick.ini
```
This runs only Priority 1 tests with shorter timeouts and faster execution.

### Running Specific Test Categories

Priority 1 tests only:
```bash
pytest tests/ -m priority1
```

Priority 2 tests only:
```bash
pytest tests/ -m priority2
```

Integration tests only:
```bash
pytest tests/ -m integration
```

Exclude slow tests:
```bash
pytest tests/ -m "not slow"
```

### Running Specific Test Files

Run only regression tests:
```bash
pytest tests/test_regression.py
```

Run specific test class:
```bash
pytest tests/test_regression.py::TestPriority1
```

Run specific test:
```bash
pytest tests/test_regression.py::TestPriority1::test_apache_detection
```

## Test Development

### Adding New Tests

1. **Determine Priority**: Classify your test as Priority 1, 2, or 3
2. **Choose Test Class**: Add to existing class or create new one
3. **Use Fixtures**: Leverage existing fixtures for consistency
4. **Mark Tests**: Use appropriate pytest markers

Example test:
```python
@pytest.mark.priority1
def test_new_feature(self, hexhttp_command, test_urls):
    """Test description."""
    result = hexhttp_command('-u', test_urls['safe'])
    assert result['success'], f"Command failed: {result['stderr']}"
    # Add specific assertions
```

### Adding Mock Server Endpoints

Add new endpoints in `mock_server.py`:

```python
@self.app.route('/new-endpoint')
def new_endpoint():
    """Description of what this endpoint simulates."""
    headers = {'Server': 'TestServer/1.0'}
    content = "<html>Test content</html>"
    return Response(content, headers=headers)
```

### Test Fixtures

Common fixtures available:

- `mock_server`: Running mock server instance
- `mock_server_url`: Base URL of mock server
- `hexhttp_command`: Function to run hexhttp commands
- `test_urls`: Dictionary of test URLs
- `temp_url_file`: Temporary file with test URLs

## Continuous Integration

The test suite is designed for CI/CD integration:

### GitHub Actions Example

```yaml
name: Tests
on: [push, pull_request]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v3
    - name: Set up Python
      uses: actions/setup-python@v4
      with:
        python-version: '3.11'
    - name: Install dependencies
      run: |
        pip install -e .[test]
    - name: Run tests
      run: |
        pytest tests/ --cov=hexhttp --cov-report=xml
```

## Test Coverage

Generate coverage reports:
```bash
pytest tests/ --cov=hexhttp --cov-report=html
```

View coverage:
```bash
open htmlcov/index.html
```

## Debugging Tests

### Verbose Output
```bash
pytest tests/ -v -s
```

### Stop on First Failure
```bash
pytest tests/ -x
```

### Run Specific Failed Test
```bash
pytest tests/test_regression.py::TestPriority1::test_apache_detection -v -s
```

### Debug Mock Server

Run mock server standalone:
```bash
python tests/mock_server.py
```

Then test endpoints manually:
```bash
curl http://127.0.0.1:8888/apache/
curl http://127.0.0.1:8888/health
```

## Best Practices

### Test Writing
1. **Clear Names**: Use descriptive test names
2. **Single Purpose**: Each test should test one thing
3. **Assertions**: Include meaningful assertion messages
4. **Cleanup**: Tests should not affect each other
5. **Documentation**: Document complex test logic

### Test Maintenance
1. **Regular Updates**: Keep tests updated with code changes
2. **Performance**: Monitor test execution time
3. **Reliability**: Fix flaky tests immediately
4. **Coverage**: Maintain good test coverage

### Mock Server
1. **Realistic**: Make mock responses realistic
2. **Consistent**: Ensure consistent behavior
3. **Documented**: Document what each endpoint simulates
4. **Maintainable**: Keep mock server code clean

## Troubleshooting

### Common Issues

**Mock server not starting:**
- Check if port 8888 is available
- Ensure Flask is installed
- Check firewall settings

**Tests timing out:**
- Increase timeout in test configuration
- Check if mock server is responding
- Verify network connectivity

**Import errors:**
- Ensure package is installed in development mode
- Check Python path
- Verify all dependencies are installed

**False test failures:**
- Check if HExHTTP behavior changed legitimately
- Update test expectations if needed
- Verify mock server responses

### Getting Help

1. Check test output for specific error messages
2. Run tests with verbose output (`-v -s`)
3. Test mock server endpoints manually
4. Check if issue is environment-specific
5. Review recent code changes

## Contributing

When contributing to the test suite:

1. **Follow Patterns**: Use existing test patterns
2. **Add Documentation**: Document new test scenarios
3. **Test Your Tests**: Ensure new tests work correctly
4. **Update README**: Update documentation as needed
5. **Consider Coverage**: Aim for good test coverage

## Future Enhancements

Planned improvements:

- [ ] Performance benchmarking tests
- [ ] More CVE-specific test scenarios
- [ ] Advanced cache poisoning simulations
- [ ] Load testing capabilities
- [ ] Test result reporting dashboard
- [ ] Automated test generation
- [ ] Cross-platform testing
