# Validate Class

The ``Validate`` class offers a robust and flexible way to handle validation logic in your PHP applications. This class simplifies and centralizes validation rules, making your code cleaner and more maintainable.

## Features
- **Simplified Code**: Reduce boilerplate and repetitive validation logic.
- **Centralized Validation Rules**: Manage all your validation logic in one place.
- **Improved Readability**: Declarative syntax for clearer, more maintainable code.
- **Extensible**: Easily add new validation rules as needed.

## Before and After
Before
Manual validation logic often leads to repetitive code:
```php
if (empty($_POST['username'])) {
    $errors[] = 'Username is required.';
} elseif (strlen($_POST['username']) < 3) {
    $errors[] = 'Username must be at least 3 characters long.';
} elseif (strlen($_POST['username']) > 20) {
    $errors[] = 'Username cannot exceed 20 characters.';
}
```

After
Using the Validate class streamlines the process:
```php
$validate = new Validate();

$validationResult = $validate->check($_POST, [
    'username' => [
        Validate::REQUIRED => ['message' => 'Username is required.'],
        Validate::MIN => ['min' => 3, 'message' => 'Username must be at least 3 characters long.'],
        Validate::MAX => ['max' => 20, 'message' => 'Username cannot exceed 20 characters.'],
    ],
]);

if ($validate->isValid()) {
    // Proceed with processing
} else {
    $errors = $validate->getErrors();
    // Handle validation errors
}
```

## Installation
To use the ``Validate`` class, simply include the class file in your project.

```
composer require hybridmind/validate
```

## Contributing
We welcome contributions to enhance the Validate class. To contribute, please follow these steps:

1. Fork the repository.
2. Create a new branch.
3. Make your changes and commit them with clear and descriptive messages.
4. Push your changes to the branch.
5. Submit a pull request.

##  License
This project is licensed under the MIT License. See the LICENSE file for details.
