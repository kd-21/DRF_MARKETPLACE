import os
from sib_api_v3_sdk import Configuration, ApiClient
from sib_api_v3_sdk.api.transactional_emails_api import TransactionalEmailsApi


# class Util:
#     @staticmethod
#     def send_email(data):
#         email = EmailMessage(
#             subject = data['subject'],
#             body= data['body'],
#             from_email = os.environ.get('EMAIL_FROM'),
#             to = [data['to_email']]
#         )
#         email.send()
        
        


class Util:
    @staticmethod
    def send_email(data):
        # Configuration for SendinBlue
        configuration = Configuration()
        configuration.api_key['api-key'] = os.getenv('SENDINBLUE_API_KEY')

        # Create an instance of the TransactionalEmailsApi
        api_instance = TransactionalEmailsApi(ApiClient(configuration))

        # Prepare the email data
        send_smtp_email = {
            "sender": {
                "name": "Marketplace Django",  
                "email": os.getenv('EMAIL_FROM')  # Use EMAIL_FROM from .env
            },
            "to": [
                {"email": data['to_email']}  # This will be the user's email
            ],
            "subject": data['subject'],
            "htmlContent": f"""
                <html>
                    <body>
                        <img src="https://www.w3schools.com/tags/img_girl.jpg" alt="Girl in a jacket" width="500" height="600">
                        <p>Click the link to reset your password:</p>
                        <a href="{data['reset_link']}">{data['reset_link']}</a>
                    </body>
                </html>
            """  # The email body in HTML
        }

        try:
            # Send the email
            response = api_instance.send_transac_email(send_smtp_email)
            return response
        except Exception as e:  # Catch any exception
            print(f"Exception when sending email: {e}")
            return None
