#Auth Thursday

##Learning Objectives

* TDD a secure authentication system from scratch in Rails
* Build RESTful routes necessary for authentication
* Design signup / login forms & a logout button

##PART 1 — User Model

## App Setup

Let's start a new Rails application:

* `rails new rails_auth_app -T -B -d postgresql`
* `cd rails_auth_app`
* `bundle`
* `rake db:create`
* `subl .`

## Model Setup

Let's leave our controllers be for the time being and setup our models.


```
rails g model user email:string password_digest:string
```

`email` is the natural username for our user, and the `password_digest` is a fancy term for a hashed password.


```
rake db:create db:migrate
```
## Authentication Review

When **authenticating** a user we are verifying their credentials prove they are who they say they are. When we are **authorizing** we are saying based on a users credentials and status they can access certain things, e.g. guest user, user, and admin all might have different permissions to access resources.


To **authenticate** our users we typically ask them for a unique pass phrase we can associate to their `email`, a **password**. A *password* is a very private piece of information that must be kept secret, and so, we strategically obscure in such a way that we can only **confirm** a user is **authentic**, but not what their *password is.* Storing a *raw password* would leave us vulnerable in the event of a successful attack that gained access to our DB.

Our library of choice for *password* obfuscation is called `BCrypt`. This will be added to our gemfile for authentication setup later. In Rails, the convention is to push more logic into our models, so it shouldn't come as a surprise that authentication setup will happen in the **user model.**

Let's uncomment the `bcrypt` at the bottom of our `Gemfile`.

`Gemfile`

```ruby
...
	# Use ActiveModel has_secure_password
	gem 'bcrypt', '~> 3.1.7'
...

```

Then run `bundle` to finish installation of `bcrypt`.

### Playing With `BCrypt`

As soon as something is installed via bundler we can access it via our `rails console.` Let's play in console.


```bash
	Loading development environment (Rails 4.1.6)
 ## Let's create our first password & save the hashed output to a variable
	2.1.0 :001 > BCrypt::Password.create("foobar")
	 => "$2a$10$6MQQCxBpfu16koDVs3zkbeSXn1z4fqKx9xLp4.UOBQBDkgFaukWM2"

 ## Let's compare our password to another
 	2.1.0 :003 > BCrypt::Password.new(hashed_pass) == "blah"
 	=> false
 	
 ## Let's compare our password to original
 	2.1.0 :004 > BCrypt::Password.new(hashed_pass) == "foobar"
 	=> true
 	
 ## Exit
 	2.1.0 :005 > exit
```


This helps us think about how we might go about setting up an **authenticate** method for a **user**.


## Test Setup

* Run the command `rails g spec:install` to initialize rspec as your testing suite.
	* Note a `spec` directory has been created for you
* Inside `spec` create the file `/models/user_spec.rb`, place in the below tests, & run the command `rspec`

```ruby
require 'rails_helper'

describe User, type: :model do

  context 'Initialization' do
    before(:each) { @user = User.new }
    it "creates a password digest after setting the password" do
      #password digest starts as nil
      expect(@user.password_digest).to be_nil
      #password is set
      @user.password = "swordfish"
      #password digest is created after passsword is set
      expect(@user.password_digest).not_to be_nil
    end
    it "ensures the password digest is not the password" do
      @user.password = "swordfish"
      expect(@user.password_digest).not_to eq(@user.password)
    end
  end

  context 'Validation' do
    before(:each) do
      #create a user in active memory
      @user = User.new({
        email: "bana@na.com",
        password: "adsf1234",
        password_confirmation: "adsf1234"
      })
    end
    it "validates presence of password_digest" do
      #clear values of password & password_confirmation
      @user.password_digest = nil
      expect(@user).not_to be_valid
    end

    it "validates password & password confirmation match" do
      @user.password_confirmation = "not the same"
      expect(@user).not_to be_valid
    end
  end

  context 'Authentication' do
    before(:each) do
      #save a user to the database
      @user = User.create({
        email: "shmee@me.com",
        password: "jumanji",
        password_confirmation: "jumanji"
      })
    end
    it "restricts passwords from saving to the db" do
      found_user = User.all.first
      expect(found_user.password).to eq(nil)
    end

    describe "#authenticate" do
      it "returns the user when the correct password is provided" do
        expect(@user.authenticate("jumanji")).to eq(@user)
      end

      it "returns false when an incorrect password is provided" do
        expect(@user.authenticate("ijnamuj")).to eq(false)
      end
    end

    describe "::confirm" do
      it "checks if a specified user & password combination exists" do
        user_email = "shmee@me.com"
        user_password = "jumanji"
        found_user = User.find_by_email(user_email)
        expect(User.confirm(user_email, user_password)).to eq(found_user.authenticate(user_password))
      end
    end
  end
end
```

## TDD Authentication

* Let's code together to write tests to build our authentication system

```ruby
class User < ActiveRecord::Base
  BCrypt::Engine.cost = 12

  validates_presence_of :email, :password_digest
  validates_confirmation_of :password

  def authenticate(unencrypted_password)
    secure_password = BCrypt::Password.new(self.password_digest)
    if secure_password == unencrypted_password
      self
    else
      false
    end
  end

  def password=(unencrypted_password)
    #raise scope of password to instance
    @password = unencrypted_password
    self.password_digest = BCrypt::Password.create(@password)
  end

  def password
    #get password, equivalent to `attr_reader :password`
    @password
  end

  def self.confirm(email_param, password_param)
    user = User.find_by({email: email_param})
    user.authenticate(password_param)
  end


end
```


## Refactor

* Let's discover how using `has_secure_password` can magically require us to write less code.


## PART II — Routing, Controllers, & Views

## Controller Setup

We will need two controllers

* **UsersController**: to handle concerns related to users: CRUD operations, and **sign_up**.
* **SessionsController**: to handle **session** related concerns: **login** and **logout**.


Let's begin by creating these controllers and their respective views


```
rails g controller users index show new edit
```

and 

```
rails g controller sessions new create destroy
```




##


##Ref

[Authentication from scratch](https://github.com/sf-wdi-15/notes/tree/master/week_07_more_rails/day_1_rails_auth/dawn_auth_start)

[Authentication from scratch 2](https://github.com/sf-wdi-17/notes/tree/master/lectures/week-07/_4_thursday/dusk)

[Simple Auth](https://github.com/sf-wdi-14/notes/blob/master/lectures/week-7/_1_monday/dawn/auth-in-rails.md)

[Authorization w/ Pundit](https://github.com/sf-wdi-17/notes/tree/master/lectures/week-07/_2_tuesday/dusk)