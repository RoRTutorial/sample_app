source 'https://rubygems.org'

gem 'rails', '3.2.7'
gem 'gravatar_image_tag'

# Bundle edge Rails instead:
# gem 'rails', :git => 'git://github.com/rails/rails.git'

group :production, :staging do
  gem "pg"
end

group :development, :test do
  gem "sqlite3", "~> 1.3.0", :require => "sqlite3"
  gem 'rspec-rails' # for ch3
  gem 'taps', :require => false # has an sqlite dependency, which heroku hates
  gem 'annotate'
  
end

group :test do
  gem 'rspec'
  gem 'webrat'
  gem 'spork'
  gem 'factory_girl_rails', :require => false
end


# Gems used only for assets and not required
# in production environments by default.
group :assets do
  gem 'sass-rails',   '~> 3.2.3'
  gem 'coffee-rails', '~> 3.2.1'

  # See https://github.com/sstephenson/execjs#readme for more supported runtimes
  # gem 'therubyracer', :platforms => :ruby

  gem 'uglifier', '>= 1.0.3'
end

gem 'jquery-rails'

# To use ActiveModel has_secure_password
# gem 'bcrypt-ruby', '~> 3.0.0'

# To use Jbuilder templates for JSON
# gem 'jbuilder'

# Use unicorn as the app server
# gem 'unicorn'

# Deploy with Capistrano
# gem 'capistrano'

# To use debugger
# gem 'debugger'