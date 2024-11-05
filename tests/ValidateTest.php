<?php
require 'vendor/autoload.php';

use YourNamespace\Validate;

$validate = new Validate();

$data = [
    'username' => 'john_doe',
    'email' => 'john.doe@example.com',
    'password' => 'Password123'
];

$rules = [
    'username' => [
        Validate::REQUIRED => ['message' => 'Username is required.'],
        Validate::MIN => ['min' => 3, 'message' => 'Username must be at least 3 characters long.'],
        Validate::MAX => ['max' => 20, 'message' => 'Username cannot exceed 20 characters.']
    ],
    'email' => [
        Validate::REQUIRED => ['message' => 'Email is required.'],
        Validate::EMAIL => ['message' => 'Email is not valid.']
    ],
    'password' => [
        Validate::REQUIRED => ['message' => 'Password is required.'],
        Validate::MIN => ['min' => 6, 'message' => 'Password must be at least 6 characters long.']
    ]
];

$validate->check($data, $rules);

if ($validate->isValid()) {
    echo "Validation passed.";
} else {
    print_r($validate->getErrors());
}
