<?php

namespace hybridmind\Validate;

use DateTime;

class Validate
{
    private array $errors = [];
    private bool $passed = false;

    const REQUIRED = 'required';
    const MAX = 'max';
    const MIN = 'min';
    const NUMERIC = 'numeric';
    const INT = 'int';
    const PRICE = 'price';
    const MIN_NUMBER = 'min_number';
    const MAX_NUMBER = 'max_number';
    const DATE = 'date';
    const IS_ARRAY = 'is_array';
    const ARRAY_HAS_ONE_NOT_EMPTY = 'array_has_one_not_empty';
    const ARRAY_HAS_ONE = 'array_has_one';
    const IN_ARRAY = 'in_array';
    const OBJECT = 'object';
    const EQUAL = 'equal';
    const NOT_EQUAL = 'not_equal';
    const DOMAIN = 'domain';
    const HTML = 'html';
    const DB_NOT_EXISTS = 'db_not_exists';
    const DB_EXISTS = 'db_exists';
    const TEXTAREA = 'textarea';
    const GREATER_THAN = 'greater_than';
    const EMAIL = 'email';
    const PREG_MATCH = 'preg_match';
    const ONLY_LATIN_LETTERS = 'only_latin_letters';
    const POST_MATCH = 'post_match';
    const POST_NOT_MATCH = 'post_not_match';

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

    public function isValid(): bool
    {
        return $this->passed;
    }

    public function getErrors(): array
    {
        return $this->errors;
    }

    private function addError(string $field, string $rule, $value, string $message): void
    {
        $this->errors[] = [
            'field' => $field,
            'rule' => $rule,
            'value' => $value,
            'message' => $message
        ];
    }

    private function validateDatabase(string $item, $value, string $rule, array $rule_value): void
    {
        // Проверка за достатъчни параметри
        if (empty($rule_value['table']) || empty($rule_value['column'])) {
            $this->addError($item, $rule, $value, "Няма достатъчно предадена информация за проверка в базата данни: {$item}");
            return;
        }

        // Изпълнение на SQL заявка за проверка
        $result = Application::DB()->query(
            "SELECT * FROM {$rule_value['table']} WHERE {$rule_value['column']} = ?",
            [$value]
        )->getFirst();

        if ($rule === self::DB_NOT_EXISTS && $result) {
            $this->addError($item, 'db_not_exists', $value, $rule_value['message']);
        } elseif ($rule === self::DB_EXISTS && $result) {  // Проверяваме дали $result е истинско
            $this->addError($item, 'db_exists', $value, $rule_value['message']);
        }
    }


    private function isValidDomain(string $value): bool
    {
        return preg_match("/^([a-z\d](-*[a-z\d])*)(\.([a-z\d](-*[a-z\d])*))*$/i", $value) &&
            preg_match("/^.{1,253}$/", $value) &&
            preg_match("/^[^\.]{1,63}(\.[^\.]{1,63})*$/", $value);
    }

    public function validatePassword($password)
    {
        $errors = [];

        if (strlen($password) < 6 || strlen($password) > 64) {
            $errors[] = 'Паролата трябва да бъде с дължина между 6 и 64 знака';
        }

        if (!preg_match('@[A-Z]@', $password)) {
            $errors[] = 'Паролата трябва да съдържа поне една главна буква';
        }

        if (!preg_match('@[a-z]@', $password)) {
            $errors[] = 'Паролата трябва да съдържа поне една малка буква';
        }

        if (!preg_match('@[0-9]@', $password)) {
            $errors[] = 'Паролата трябва да съдържа поне една цифра';
        }

        if (!empty($errors)) {
            $this->handleErrors($errors);
        }

        return cleanInput($password);
    }

    private function handleErrors($errors)
    {
        redirection(getRequestPage(), implode(", ", $errors), 'info');
        exit();
    }
}
