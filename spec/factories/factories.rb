require 'factory_girl'

# By using the symbol ':user', we get Factory Girl to simulate the User model.
FactoryGirl.define do
   factory :user do |user|
	   user.name "Michael Hartl"
	   user.email "mhartl@example.com"
	   user.password "foobar"
	   user.password_confirmation "foobar"
   end 
end