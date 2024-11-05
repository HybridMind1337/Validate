<?php

namespace hybridmind\Validate;

use DateTime;

class Validate
{
    private array $errors = [];
    private bool $passed = false;

    // Constants representing validation rules
    const REQUIRED = 'required';  // Ensures the value is not empty
    const MAX = 'max';  // Ensures the value does not exceed a maximum length
    const MIN = 'min';  // Ensures the value meets a minimum length
    const NUMERIC = 'numeric';  // Ensures the value is numeric
    const INT = 'int';  // Ensures the value is an integer
    const PRICE = 'price';  // Ensures the value is a valid price format
    const MIN_NUMBER = 'min_number';  // Ensures the value is greater than or equal to a minimum number
    const MAX_NUMBER = 'max_number';  // Ensures the value is less than or equal to a maximum number
    const DATE = 'date';  // Ensures the value is a valid date
    const IS_ARRAY = 'is_array';  // Ensures the value is an array
    const ARRAY_HAS_ONE_NOT_EMPTY = 'array_has_one_not_empty';  // Ensures the array has at least one non-empty value
    const ARRAY_HAS_ONE = 'array_has_one';  // Ensures the array has at least one value
    const IN_ARRAY = 'in_array';  // Ensures the value is in a specified array
    const OBJECT = 'object';  // Ensures the value is an object
    const EQUAL = 'equal';  // Ensures the value equals a specified value
    const NOT_EQUAL = 'not_equal';  // Ensures the value does not equal a specified value
    const DOMAIN = 'domain';  // Ensures the value is a valid domain
    const HTML = 'html';  // Ensures the value contains HTML tags
    const DB_NOT_EXISTS = 'db_not_exists';  // Ensures the value does not exist in the database
    const DB_EXISTS = 'db_exists';  // Ensures the value exists in the database
    const TEXTAREA = 'textarea';  // Ensures the value is not empty when trimmed
    const GREATER_THAN = 'greater_than';  // Ensures the value is greater than another field's value
    const EMAIL = 'email';  // Ensures the value is a valid email address
    const PREG_MATCH = 'preg_match';  // Ensures the value matches a specified regular expression
    const ONLY_LATIN_LETTERS = 'only_latin_letters';  // Ensures the value contains only Latin letters
    const POST_MATCH = 'post_match';  // Ensures the value matches another field's value
    const POST_NOT_MATCH = 'post_not_match';  // Ensures the value does not match another field's value

    /**
     * Checks an array of items against a set of rules.
     * 
     * @param array $items The items to check.
     * @param array $source The source data to validate.
     * @return self
     */
    public function check(array $items, array $source): self
    {
        foreach ($items as $item => $rules) {
            foreach ($rules as $rule => $rule_value) {
                $value = $source[$item] ?? '';
                $item = htmlspecialchars(str_replace('&amp;', '&', $item), ENT_QUOTES);

                if ($rule === self::REQUIRED && empty($value)) {
                    $this->addError($item, 'required', $value, $rule_value['message']);
                }

                switch ($rule) {
                    case self::MIN:
                        if (mb_strlen($value) < $rule_value['min']) {
                            $this->addError($item, 'min', $value, $rule_value['message']);
                        }
                        break;

                    case self::MAX:
                        if (mb_strlen($value) > $rule_value['max']) {
                            $this->addError($item, 'max', $value, $rule_value['message']);
                        }
                        break;

                    case self::NUMERIC:
                        if (!is_numeric($value)) {
                            $this->addError($item, 'numeric', $value, $rule_value['message']);
                        }
                        break;

                    case self::INT:
                        if (filter_var($value, FILTER_VALIDATE_INT) === false) {
                            $this->addError($item, 'int', $value, $rule_value['message']);
                        }
                        break;

                    case self::PRICE:
                        if (!preg_match('/^[\d]*(,\d{2})*?(.\d{2})?$/', $value)) {
                            $this->addError($item, 'price', $value, $rule_value['message']);
                        }
                        break;

                    case self::MIN_NUMBER:
                        if ($rule_value['min'] > $value) {
                            $this->addError($item, 'min_number', $value, $rule_value['message']);
                        }
                        break;

                    case self::MAX_NUMBER:
                        if ($rule_value['max'] < $value) {
                            $this->addError($item, 'max_number', $value, $rule_value['message']);
                        }
                        break;

                    case self::DATE:
                        if (!DateTime::createFromFormat($rule_value['format'] ?? 'Y-m-d', $value)) {
                            $this->addError($item, 'date', $value, $rule_value['message']);
                        }
                        break;

                    case self::DOMAIN:
                        if (!$this->isValidDomain($value)) {
                            $this->addError($item, 'domain', $value, $rule_value['message']);
                        }
                        break;

                    case self::HTML:
                        if ($value === strip_tags($value)) {
                            $this->addError($item, 'html', $value, $rule_value['message']);
                        }
                        break;

                    case self::DB_NOT_EXISTS:
                    case self::DB_EXISTS:
                        $this->validateDatabase($item, $value, $rule, $rule_value);
                        break;

                    case self::TEXTAREA:
                        if (!strlen(trim($value))) {
                            $this->addError($item, 'textarea', $value, $rule_value['message']);
                        }
                        break;

                    case self::IN_ARRAY:
                        if (!in_array($value, $rule_value['in_array'] ?? [])) {
                            $this->addError($item, 'in_array', $value, $rule_value['message']);
                        }
                        break;

                    case self::GREATER_THAN:
                        if ($value < $source[$rule_value['than']]) {
                            $this->addError($item, 'greater_than', $value, $rule_value['message']);
                        }
                        break;

                    case self::EMAIL:
                        if (!filter_var($value, FILTER_VALIDATE_EMAIL)) {
                            $this->addError($item, 'email', $value, $rule_value['message']);
                        }
                        break;

                    case self::EQUAL:
                        if ($value === $rule_value['value']) {
                            $this->addError($item, 'equal', $value, $rule_value['message']);
                        }
                        break;

                    case self::NOT_EQUAL:
                        if ($value !== $rule_value['value']) {
                            $this->addError($item, 'not_equal', $value, $rule_value['message']);
                        }
                        break;

                    case self::PREG_MATCH:
                        if (!preg_match($rule_value['pattern'], $value)) {
                            $this->addError($item, 'preg_match', $value, $rule_value['message']);
                        }
                        break;

                    case self::ONLY_LATIN_LETTERS:
                        if (preg_match('/[^\p{Common}\p{Latin}]/u', $value)) {
                            $this->addError($item, 'only_latin_letters', $value, $rule_value['message']);
                        }
                        break;

                    case self::POST_MATCH:
                        if ($value === $source[$rule_value['value']]) {
                            $this->addError($item, 'post_match', $value, $rule_value['message']);
                        }
                        break;

                    case self::POST_NOT_MATCH:
                        if ($value !== $source[$rule_value['value']]) {
                            $this->addError($item, 'post_not_match', $value, $rule_value['message']);
                        }
                        break;

                    case self::IS_ARRAY:
                        if (!is_array($value)) {
                            $this->addError($item, 'is_array', $value, $rule_value['message']);
                        }
                        break;

                    case self::ARRAY_HAS_ONE_NOT_EMPTY:
                        if (!is_array($value) || empty($value)) {
                            $this->addError($item, 'array_has_one_not_empty', $value, $rule_value['message']);
                        }
                        break;

                    case self::ARRAY_HAS_ONE:
                        if (!is_array($value) || empty($value)) {
                            $this->addError($item, 'array_has_one', $value, $rule_value['message']);
                        }
                        break;
                }
            }
        }

        if (empty($this->errors)) {
            $this->passed = true;
        }

        return $this;
    }

    /**
     * Checks if the validation passed.
     * 
     * @return bool True if validation passed, otherwise false.
     */
    public function isValid(): bool
    {
        return $this->passed;
    }

    /**
     * Returns the validation errors.
     * 
     * @return array The validation errors.
     */
    public function getErrors(): array
    {
        return $this->errors;
    }

    /**
     * Adds an error to the errors array.
     * 
     * @param string $field The field name.
     * @param string $rule The validation rule.
     * @param mixed $value The value that failed validation.
     * @param string $message The error message.
     */
    private function addError(string $field, string $rule, $value, string $message): void
    {
        $this->errors[] = [
            'field' => $field,
            'rule' => $rule,
            'value' => $value,
            'message' => $message
        ];
    }

    /**
     * Validates the value against database records.
     * 
     * @param string $item The item name.
     * @param mixed $value The value to check.
     * @param string $rule The validation rule.
     * @param array $rule_value The rule parameters.
     */
    private function validateDatabase(string $item, $value, string $rule, array $rule_value): void
    {
        // Ensure sufficient parameters are provided
        if (empty($rule_value['table']) || empty($rule_value['column'])) {
            $this->addError($item, $rule, $value, "Insufficient information provided for database check: {$item}");
            return;
        }

        // Execute SQL query to check
        $result = Application::DB()->query(
            "SELECT * FROM {$rule_value['table']} WHERE {$rule_value['column']} = ?",
            [$value]
        )->getFirst();

        if ($rule === self::DB_NOT_EXISTS && $result) {
            $this->addError($item, 'db_not_exists', $value, $rule_value['message']);
        } elseif ($rule === self::DB_EXISTS && !$result) {
            $this->addError($item, 'db_exists', $value, $rule_value['message']);
        }
    }

    /**
     * Validates if the value is a valid domain.
     * 
     * @param string $value The value to check.
     * @return bool True if valid, otherwise false.
     */
    private function isValidDomain(string $value): bool
    {
        return preg_match("/^([a-z\d](-*[a-z\d])*)(\.([a-z\d](-*[a-z\d])*))*$/i", $value) &&
            preg_match("/^.{1,253}$/", $value) &&
            preg_match("/^[^\.]{1,63}(\.[^\.]{1,63})*$/", $value);
    }

    /**
     * Validates a password according to specific rules.
     * 
     * @param string $password The password to check.
     * @return string The cleaned password.
     */
    public function validatePassword($password)
    {
        $errors = [];

        if (strlen($password) < 6 || strlen($password) > 64) {
            $errors[] = 'Password must be between 6 and 64 characters long';
        }

        if (!preg_match('@[A-Z]@', $password)) {
            $errors[] = 'Password must contain at least one uppercase letter';
        }

        if (!preg_match('@[a-z]@', $password)) {
            $errors[] = 'Password must contain at least one lowercase letter';
        }

        if (!preg_match('@[0-9]@', $password)) {
            $errors[] = 'Password must contain at least one digit';
        }

        if (!empty($errors)) {
            $this->handleErrors($errors);
        }

        return cleanInput($password);
    }

    /**
     * Handles errors by redirecting to the request page with an error message.
     * 
     * @param array $errors The errors to handle.
     */
    private function handleErrors($errors)
    {
        redirection(getRequestPage(), implode(", ", $errors), 'info');
        exit();
    }
}
