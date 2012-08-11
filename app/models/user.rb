# == Schema Information
#
# Table name: users
#
#  id         :integer          not null, primary key
#  name       :string(255)
#  email      :string(255)
#  created_at :datetime         not null
#  updated_at :datetime         not null
#

require 'digest'
class User < ActiveRecord::Base
  
  attr_accessor :password
  
  attr_accessible :email, :name, :password, :password_confirmation 
  
  email_regex = /\A[\w+\-.]+@[a-z\d\-.]+\.[a-z]+\z/i
  validates :email, :presence => true,
                    :format   => { :with => email_regex },
                    :uniqueness =>  { :case_sensitive => false }
                    
  validates :name,  :presence => true,
                    :length   => { :maximum => 50 }    
                    
  # Automatically create the virtual attribute 'password_confirmation'.
  validates :password,  :presence => true,
                        :confirmation => true,
                        :length => { :within => 6..40 }
                        
  before_save :encrypt_password
  
  def has_password?(submitted_password)
    encrypted_password == encrypted(submitted_password)
  end
  
  private
    
    def encrypt_password
      self.salt = make_salt if new_record?
      self.encrypted_password = encrypted(password)
    end
    
    def encrypted(string)
      secure_hash("#{salt}--#{string}")
    end
    
    def make_salt
      secure_hash("#{Time.now.utc}--#{password}")
    end
    
    def secure_hash(string)
      Digest::SHA2.hexdigest(string)
    end
end
