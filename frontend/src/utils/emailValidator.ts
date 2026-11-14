/**
 * Real Email Validator for አሻራ Registration & Custody Ledger
 * Ensures users register with genuine, valid, non-disposable email addresses.
 */

// Disposable / temporary burner email domains
const DISPOSABLE_DOMAINS = new Set([
  'tempmail.com', 'temp-mail.org', 'temp-mail.io', '10minutemail.com', '10minutemail.net',
  'mailinator.com', 'guerrillamail.com', 'guerrillamail.net', 'guerrillamail.org',
  'sharklasers.com', 'grr.la', 'guerrillamailblock.com', 'pokemail.net', 'spam4.me',
  'yopmail.com', 'yopmail.fr', 'yopmail.net', 'trashmail.com', 'trashmail.net',
  'trashmail.me', 'throwawaymail.com', 'dispostable.com', 'maildrop.cc',
  'getairmail.com', 'mohmal.com', 'crazymailing.com', 'fakemailgenerator.com',
  'inboxkitten.com', 'burnermail.io', 'tempinbox.com', 'fakeinbox.com',
  'generator.email', 'dropmail.me', 'tempr.email', 'disposablemail.com',
  'nada.ltd', 'getnada.com', 'mytemp.email', 'emailondeck.com', 'minutemailbox.com'
]);

// Dummy, placeholder, and test domains
const FAKE_DOMAINS = new Set([
  'example.com', 'example.org', 'example.net', 'test.com', 'testing.com',
  'fake.com', 'dummy.com', 'sample.com', 'asdf.com', 'qwerty.com',
  'foo.com', 'bar.com', 'none.com', 'nowhere.com', 'invalid.com',
  'fakeemail.com', 'testmail.com', 'temp.com', 'xyz.com', 'abc.com',
  'mailinator.net', 'domain.com', 'sample.org', 'test.net'
]);

// Known fake or placeholder usernames
const FAKE_USERNAMES = new Set([
  'test', 'testing', 'fake', 'dummy', 'asdf', 'asdfgh', 'asdfghjk',
  'qwerty', 'qwertyuiop', '12345', '123456', '12345678', 'user',
  'username', 'noone', 'nobody', 'sample', 'null', 'undefined', 'anonymous'
]);

export interface EmailValidationResult {
  isValid: boolean;
  error?: string;
}

/**
 * Validates whether an email is a real, legitimate email address.
 */
export function validateRealEmail(email: string): EmailValidationResult {
  const trimmed = email.trim().toLowerCase();

  if (!trimmed) {
    return { isValid: false, error: 'Email address is required.' };
  }

  // Must have standard RFC email syntax
  const basicEmailRegex = /^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+$/;
  if (!basicEmailRegex.test(trimmed)) {
    return { isValid: false, error: 'Please enter a valid email address (e.g. name@domain.com).' };
  }

  // Check for consecutive dots
  if (trimmed.includes('..')) {
    return { isValid: false, error: 'Email cannot contain consecutive dots (..).' };
  }

  const parts = trimmed.split('@');
  if (parts.length !== 2) {
    return { isValid: false, error: 'Email address must contain exactly one "@" symbol.' };
  }

  const [username, domain] = parts;

  // Local part length check
  if (username.length < 2) {
    return { isValid: false, error: 'Email username must be at least 2 characters long.' };
  }

  if (username.length > 64) {
    return { isValid: false, error: 'Email username is too long.' };
  }

  // Disallow obvious fake usernames
  if (FAKE_USERNAMES.has(username)) {
    return { isValid: false, error: `Placeholder usernames like "${username}" are not permitted. Please use your real email.` };
  }

  // Domain structure checks
  const domainParts = domain.split('.');
  if (domainParts.length < 2) {
    return { isValid: false, error: 'Email domain must have a valid extension (e.g. .com, .gov, .org).' };
  }

  const domainName = domainParts[0];
  const tld = domainParts[domainParts.length - 1];

  if (domainName.length < 2) {
    return { isValid: false, error: 'Email domain name is too short to be a valid provider.' };
  }

  // TLD must only be letters and between 2 and 24 characters
  if (!/^[a-z]{2,24}$/.test(tld)) {
    return { isValid: false, error: 'Email has an invalid domain extension (TLD).' };
  }

  // Check for disposable burner domains
  if (DISPOSABLE_DOMAINS.has(domain)) {
    return { isValid: false, error: 'Temporary or disposable email addresses are not permitted. Please provide a real email.' };
  }

  // Check for fake / placeholder domains
  if (FAKE_DOMAINS.has(domain)) {
    return { isValid: false, error: 'Test and placeholder domains like "' + domain + '" are not allowed. Please enter your real email.' };
  }

  // Check if domain looks like an obvious random keyboard smash e.g. "asdfghjk.com"
  if (/^(?:asdf|qwerty|zxcv|1234|qwer)/.test(domainName) && domainParts.length === 2) {
    return { isValid: false, error: 'Please enter a real email address from a legitimate provider or agency.' };
  }

  return { isValid: true };
}
