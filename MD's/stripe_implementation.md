so scan all my files aswell as both my auth files from my web applciation but also my ios app. my web applcition has teh backedn route/model code for users login regsiter etc etc becasue bascially i have a web applcitionba d im in the porcess of making an IOS app for it aswell where everything is in sync obviolsy. so essentially i want to have easy susbcreiptions for ios where they can sign up/buy with apple susbcriptiona dn like theri apple wallet i guess and stripe alsof if possible but mainly i woudl liek the apple sucbription way. so for my web applcition i cnat use apples subscription thing so i am doing stripe adn im gonan do it teh eay where they handle teh payemtn an dtsuff but i fully write teh code myself for it basically-refer to documentiation ill provide. so teh thing is i need both sign ups to be in sync with each other. so i think i have this datasbe susbcription active/non active already somehwat set up but now i need ot put it all togethor and maek sure it reslly is all configured correctly in terms of user subscriptions. so to say again- i have my ios app where they will susbcribe with apples service and makes their user acoutn and then for my web applcition that same user will have a subscription active since they did it on iphone/ios. teh same applies in reverse where if a user signs up on teh web applcition (with stripe) then they also have an accoutn on ios sicne its teh same app togethor- liek all data fopr a user is in sync and perstatnt over the ios and web app. teh ios app shoudl be configured correctly for that because i just connect to the backend routes but we haev to figure out the regsietring/login/auth. also isnce i have oauth in my web app and then normal regsierting (no oauth) all 3 have to be otpions for the ios app sign in aswell. so if tehy sign up on ios whcih will most liekly most of the time be apple sign up sinc ewell there on iphone lol then they can sign in on web app aswell with apple, saem appleis fro google, adn saem applies for normal registartion/sign up and same applei sin reverse where if they sign up on web app with any of those it applies to the ios app aswell.

so im gonn aprovid eyou my ios app auth files, aswell as teh api configs, aswella s teh userslice

for teh web app file sill provide you the relavant routes like user/login/register etc etc routes, oauth routes, aswell as the databse models and databse configs and fucntions. aswell as all teh auth pages in teh weeb app, aswell as its userlsice and userproilfe and app.js and maybe other important files

so we need to do a few things. first we need to make sure both ios and web app are confihgured correctly for what i just mentioed (i havent implemened the apple subscription thing yet fro ios but i guess make it a placehodler and get it compellty ready for it). also we need to make teh stripe integartion for my web app and make the pay page and anything else needed and edit any auth files as needed for it. i think its close to being all set up iun my web app and we just add teh stripe thing but just in case makes sure the auth files or any backend files are set up correcty-0 we might need to add backedn files/routes/edit backend routes aswell fro stripe or whatver and make sure the sucbritipons ar eall in sync with ios and web app. aalso make sure my iso app is configured correctly fro teh user susbcription sync aswell(even tho it does just connect to the abckend web app but idk mayeb teh suerlcie is nt ready yet or soemthing aslong teh line so fthat so just triple check (and dont just say soemthing is worng becasue i said that, actually make sure)


teh ios app is teh certgames repo

the web app is teh porxyauthrequired repo

ok and so far fro stripe all ive done is sign up, amd n=make teh product or whatever in theri page wher eit sa recauring payemnt of 9.99 and stuff tahst all ive doen so far. so now we need ot do whastevr we need to do where we make out custom page/code or whatver and i want to make it as easy as possibeol fro peopole to sign up. alof if possible sicne teh webspite is aslo confihguired to look good on mobile devices web (liek its mobiel ddevice friendly teh web app aswell) so mayeb if tehy have a wallet option to pay and somehwo deetct liek we do with css reposeness if screen width is small it can offer wallet pay but if thats not possobel ist whatver. i bacialy am jjust tryiong to make it as easy as humanly possible to pay fro a subscription so whatver we need to do to do to that and if on mobile device (web) then offers wallet pay if even possible. and liek i said for ios tho its just through apple themsleevs

addionally here is teh documentiaon for the web app stripe implemenation wehere bacially i write teh code (and they actually handle teh payemnt ands stuff)

Stripe-hosted page

Embedded form

Custom flow
Fixed-price subscription page with Payment Element
Some code
Customize with the Appearance API.

Interested in using Stripe Billing?
We’re developing a Payment Element integration that helps manage subscription features, including free trials, billing cycle anchors, and proration. Learn more about building a checkout form with embedded components.

Use this guide to learn how to sell fixed-price subscriptions. You’ll use the Payment Element to create a custom payment form that you embed in your application.

If you don’t want to build a custom payment form, you can integrate with Checkout. For an immersive version of that end-to-end integration guide, see the Billing quickstart.

If you aren’t ready to code an integration, you can set up basic subscriptions manually in the Dashboard. You can also use Payment Links to set up subscriptions without writing any code. Learn more about designing an integration to understand the decisions you need to make and the resources you need.

What you’ll build
This guide shows you how to:

Model your business by building a product catalog.
Build a registration process that creates a customer.
Create subscriptions and collect payment information.
Test and monitor payment and subscription status.
Let customers change their plan or cancel the subscription.
How to model it on Stripe
Subscriptions simplify your billing by automatically creating Invoices and PaymentIntents for you. To create and activate a subscription, you need to first create a Product to model what is being sold, and a Price which determines the interval and amount to charge. You also need a Customer to store PaymentMethods used to make each recurring payment.








A diagram illustrating common billing objects and their relationships
API object definitions
Set up Stripe
Install the Stripe client of your choice:

Command Line
Select a language


# Available as a gem
sudo gem install stripe
Gemfile
Select a language


# If you use bundler, you can add this line to your Gemfile
gem 'stripe'
And then install the Stripe CLI. The CLI provides webhook testing and you can run it to make API calls to Stripe. This guide shows how to use the CLI to set up a pricing model in a later section.

Command Line
Select a language


# 1. Download the latest `windows` zip file from
# https://github.com/stripe/stripe-cli/releases/latest

# 2. Unzip the `stripe_X.X.X_windows_x86_64.zip` file

# 3. Run the unzipped `.exe` file

# Connect the CLI to your dashboard
stripe login
For additional install options, see Get started with the Stripe CLI.

Create the pricing model
Stripe CLI or Dashboard
Build the pricing model with Products and Prices. Read the docs to learn more about pricing models.

Name
Sunglasses, premium plan, etc.
Price
0.00

USD
Billing period

Monthly

Create test product
More options
Create the customer
Client and Server
Stripe needs a customer for each subscription. In your application frontend, collect any necessary information from your users and pass it to the backend.

If you need to collect address details, the Address Element enables you to collect a shipping or billing address for your customers. For more information on the Address Element, visit the Address Element page.

register.html


<form id="signup-form">
  <label>
    Email
    <input id="email" type="email" placeholder="Email address" value="test@example.com" required />
  </label>

  <button type="submit">
    Register
  </button>
</form>
register.js


const emailInput = document.querySelector('#email');

fetch('/create-customer', {
  method: 'post',
  headers: {
    'Content-Type': 'application/json',
  },
  body: JSON.stringify({
    email: emailInput.value,
  }),
}).then(r => r.json());
On the server, create the Stripe customer object.

Command Line
Select a language



curl https://api.stripe.com/v1/customers \
  -u "sk_test_51R3wApPWNlED7CRw3AtCQrC6KaIRsKG7sG1szxtNSRLcNsvAOB83iR6kqU0d1EQXrWMLBllcMNggKZAXLxK9A7Iy00HDEzJYo5:" \
  -d email={{CUSTOMER_EMAIL}} \
  -d name={{CUSTOMER_NAME}} \
  -d "shipping[address][city]"=Brothers \
  -d "shipping[address][country]"=US \
  -d "shipping[address][line1]"="27 Fredrick Ave" \
  -d "shipping[address][postal_code]"=97712 \
  -d "shipping[address][state]"=CA \
  -d "shipping[name]"={{CUSTOMER_NAME}} \
  -d "address[city]"=Brothers \
  -d "address[country]"=US \
  -d "address[line1]"="27 Fredrick Ave" \
  -d "address[postal_code]"=97712 \
  -d "address[state]"=CA
Create the subscription
Client and Server
Note
If you want to render the Payment Element without first creating a subscription, see Collect payment details before creating an Intent.

Let your new customer choose a plan and then create the subscription—in this guide, they choose between Basic and Premium.

On the frontend, pass the selected price ID and the ID of the customer record to the backend.

prices.js


fetch('/create-subscription', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
  },
  body: JSON.stringify({
    priceId: priceId,
    customerId: customerId,
  }),
})
On the backend, create the subscription with status incomplete using payment_behavior=default_incomplete. Then return the client_secret from the subscription’s first payment intent to the frontend to complete payment.

Set save_default_payment_method to on_subscription to save the payment method as the default for a subscription when a payment succeeds. Saving a default payment method increases the success rate of future subscription payments.

server.rb
Select a language


# Set your secret key. Remember to switch to your live secret key in production.
# See your keys here: https://dashboard.stripe.com/apikeys
Stripe.api_key = 'sk_test_51R3wApPWNlED7CRw3AtCQrC6KaIRsKG7sG1szxtNSRLcNsvAOB83iR6kqU0d1EQXrWMLBllcMNggKZAXLxK9A7Iy00HDEzJYo5'

post '/create-subscription' do
  content_type 'application/json'
  data = JSON.parse(request.body.read)
  customer_id = cookies[:customer]
  price_id = data['priceId']

  # Create the subscription. Note we're expanding the Subscription's
  # latest invoice and that invoice's payment_intent
  # so we can pass it to the front end to confirm the payment
  subscription = Stripe::Subscription.create(
    customer: customer_id,
    items: [{
      price: price_id,
    }],
    payment_behavior: 'default_incomplete',
    payment_settings: {save_default_payment_method: 'on_subscription'},
    expand: ['latest_invoice.payment_intent']
  )

  { subscriptionId: subscription.id, clientSecret: subscription.latest_invoice.payment_intent.client_secret }.to_json
end
Note
If you’re using a multi-currency Price, use the currency parameter to tell the Subscription which of the Price’s currencies to use. (If you omit the currency parameter, then the Subscription uses the Price’s default currency.)

At this point the Subscription is inactive and awaiting payment. Here’s an example response. The minimum fields to store are highlighted, but store whatever your application frequently accesses.



{
  "id": "sub_JgRjFjhKbtD2qz",
  "object": "subscription",
  "application_fee_percent": null,
  "automatic_tax": {
    "enabled": false
  },
  "billing": "charge_automatically",
  "billing_cycle_anchor": 1623873347,
  "billing_thresholds": null,
See all 395 lines
Collect payment information
Client
Use Stripe Elements to collect payment details and activate the subscription. You can customize Elements to match the look-and-feel of your application.

Note
If you’re building an integration with Stripe Elements, Link enables you to create frictionless payments for your customers. They can save, change, and manage all their payment details in Link without any impact to your integration. Meanwhile, as Stripe adds support for more payment methods to Link, your integration can automatically accept them, without requiring you to make changes to your Payment methods settings.

The Payment Element securely collects all necessary payment details for a wide variety of payments methods. The payment methods currently supported by both the Payment Element and Subscriptions are credit cards, Link, SEPA Direct Debit, and BECS Direct Debit.

Set up Stripe Elements
The Payment Element is automatically available as a feature of Stripe.js. Include the Stripe.js script on your checkout page by adding it to the head of your HTML file. Always load Stripe.js directly from js.stripe.com to remain PCI compliant. Don’t include the script in a bundle or host a copy of it yourself.

subscribe.html


<head>
  <title>Checkout</title>
  <script src="https://js.stripe.com/v3/"></script>
</head>
<body>
  <!-- content here -->
</body>
Create an instance of Stripe with the following JavaScript on your checkout page:

subscribe.js


// Set your publishable key: remember to change this to your live publishable key in production
// See your keys here: https://dashboard.stripe.com/apikeys
const stripe = Stripe('pk_test_51R3wApPWNlED7CRwoI9NVW18jS19ST223UgYy5rS0hent1TAE7mPcijOusWGz0CuYtYOYwJTtUffWS9xw7gqHOAe00TPYn7tFM');
Add the Payment Element to your page
The Payment Element needs a place to live on your payment page. Create an empty DOM node (container) with a unique ID in your payment form.

subscribe.html


<form id="payment-form">
  <div id="payment-element">
    <!-- Elements will create form elements here -->
  </div>
  <button id="submit">Subscribe</button>
  <div id="error-message">
    <!-- Display error message to your customers here -->
  </div>
</form>
When the form above has loaded, create an instance of the Payment Element and mount it to the container DOM node. In the create the subscription step, you passed the client_secret value to the frontend. Pass this value as an option when creating an instance of Elements.

subscribe.js


const options = {
  clientSecret: '{{CLIENT_SECRET}}',
  // Fully customizable with appearance API.
  appearance: {/*...*/},
};

// Set up Stripe.js and Elements to use in checkout form, passing the client secret obtained in step 5
const elements = stripe.elements(options);

const paymentElementOptions = {
  layout: "tabs",
};

// Create and mount the Payment Element
const paymentElement = elements.create('payment', paymentElementOptions);
paymentElement.mount('#payment-element');
The Payment Element renders a dynamic form that allows your customer to select a payment method. The form automatically collects all necessary payments details for the payment method that they select.

Optional Payment Element configurations
Customize the Payment Element to match the design of your site by passing the appearance object into options when creating an instance of Elements.
Configure the Apple Pay interface to return a merchant token to support recurring, auto reload, and deferred payments.
Complete payment
Use stripe.confirmPayment to complete the payment using details from the Payment Element and activate the subscription. This creates a PaymentMethod and confirms the incomplete Subscription’s first PaymentIntent, causing a charge to be made. If Strong Customer Authentication (SCA) is required for the payment, the Payment Element handles the authentication process before confirming the PaymentIntent.

Provide a return_url to this function to indicate where Stripe redirects the user after they complete the payment. Your user might first be redirected to an intermediate site, like a bank authorization page, before being redirected to the return_url. Card payments immediately redirect to the return_url when a payment is successful.

subscribe.js


const form = document.getElementById('payment-form');

form.addEventListener('submit', async (event) => {
  event.preventDefault();

  const {error} = await stripe.confirmPayment({
    //`Elements` instance that was used to create the Payment Element
    elements,
    confirmParams: {
      return_url: "https://example.com/order/123/complete",
    }
  });

  if (error) {
    // This point will only be reached if there is an immediate error when
    // confirming the payment. Show error to your customer (for example, payment
    // details incomplete)
    const messageContainer = document.querySelector('#error-message');
    messageContainer.textContent = error.message;
  } else {
    // Your customer will be redirected to your `return_url`. For some payment
    // methods like iDEAL, your customer will be redirected to an intermediate
    // site first to authorize the payment, then redirected to the `return_url`.
  }
});
When your customer submits a payment, Stripe redirects them to the return_url and includes the following URL query parameters. The return page can use them to get the status of the PaymentIntent so it can display the payment status to the customer.

When you specify the return_url, you can also append your own query parameters for use on the return page.

Parameter	Description
payment_intent	The unique identifier for the PaymentIntent.
payment_intent_client_secret	The client secret of the PaymentIntent object.
When the customer is redirected back to your site, you can use the payment_intent_client_secret to query for the PaymentIntent and display the transaction status to your customer.

Caution
If you have tooling that tracks the customer’s browser session, you might need to add the stripe.com domain to the referrer exclude list. Redirects cause some tools to create new sessions, which prevents you from tracking the complete session.

Use one of the query parameters to retrieve the PaymentIntent. Inspect the status of the PaymentIntent to decide what to show your customers. You can also append your own query parameters when providing the return_url, which persist through the redirect process.

status.js


// Initialize Stripe.js using your publishable key
const stripe = Stripe('pk_test_51R3wApPWNlED7CRwoI9NVW18jS19ST223UgYy5rS0hent1TAE7mPcijOusWGz0CuYtYOYwJTtUffWS9xw7gqHOAe00TPYn7tFM');

// Retrieve the "payment_intent_client_secret" query parameter appended to
// your return_url by Stripe.js
const clientSecret = new URLSearchParams(window.location.search).get(
  'payment_intent_client_secret'
);

// Retrieve the PaymentIntent
stripe.retrievePaymentIntent(clientSecret).then(({paymentIntent}) => {
  const message = document.querySelector('#message')

  // Inspect the PaymentIntent `status` to indicate the status of the payment
  // to your customer.
  //
  // Some payment methods will [immediately succeed or fail][0] upon
  // confirmation, while others will first enter a `processing` state.
  //
  // [0]: https://stripe.com/docs/payments/payment-methods#payment-notification
  switch (paymentIntent.status) {
    case 'succeeded':
      message.innerText = 'Success! Payment received.';
      break;

    case 'processing':
      message.innerText = "Payment processing. We'll update you when payment is received.";
      break;

    case 'requires_payment_method':
      message.innerText = 'Payment failed. Please try another payment method.';
      // Redirect your user back to your payment page to attempt collecting
      // payment again
      break;

    default:
      message.innerText = 'Something went wrong.';
      break;
  }
});
Listen for webhooks
Server
To complete the integration, you need to process webhooks sent by Stripe. These are events triggered whenever state inside of Stripe changes, such as subscriptions creating new invoices. In your application, set up an HTTP handler to accept a POST request containing the webhook event, and verify the signature of the event:

server.rb
Select a language


# Set your secret key. Remember to switch to your live secret key in production.
# See your keys here: https://dashboard.stripe.com/apikeys
Stripe.api_key = 'sk_test_51R3wApPWNlED7CRw3AtCQrC6KaIRsKG7sG1szxtNSRLcNsvAOB83iR6kqU0d1EQXrWMLBllcMNggKZAXLxK9A7Iy00HDEzJYo5'

post '/webhook' do
  # You can use webhooks to receive information about asynchronous payment events.
  # For more about our webhook events check out https://stripe.com/docs/webhooks.
  webhook_secret = ENV['STRIPE_WEBHOOK_SECRET']
  payload = request.body.read
  if !webhook_secret.empty?
See all 62 lines
During development, use the Stripe CLI to observe webhooks and forward them to your application. Run the following in a new terminal while your development app is running:

Command Line


stripe listen --forward-to localhost:4242/webhook
For production, set up a webhook endpoint URL in the Dashboard, or use the Webhook Endpoints API.

You’ll listen to a couple of events to complete the remaining steps in this guide. See Subscription events for more details about subscription-specific webhooks.

Provision access to your service
Client and Server
Now that the subscription is active, give your user access to your service. To do this, listen to the customer.subscription.created, customer.subscription.updated, and customer.subscription.deleted events. These events pass a subscription object which contains a status field indicating whether the subscription is active, past due, or canceled. See the subscription lifecycle for a complete list of statuses.

In your webhook handler:

Verify the subscription status. If it’s active then your user has paid for your product.
Check the product the customer subscribed to and grant access to your service. Checking the product instead of the price gives you more flexibility if you need to change the pricing or billing interval.
Store the product.id, subscription.id and subscription.status in your database along with the customer.id you already saved. Check this record when determining which features to enable for the user in your application.
The state of a subscription might change at any point during its lifetime, even if your application does not directly make any calls to Stripe. For example, a renewal might fail due to an expired credit card, which puts the subscription into a past due state. Or, if you implement the customer portal, a user might cancel their subscription without directly visiting your application. Implementing your handler correctly keeps your application state in sync with Stripe.

Cancel the subscription
Client and Server
It’s common to allow customers to cancel their subscriptions. This example adds a cancellation option to the account settings page.

Sample subscription cancelation interface.
Account settings with the ability to cancel the subscription

script.js


function cancelSubscription(subscriptionId) {
  return fetch('/cancel-subscription', {
    method: 'post',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      subscriptionId: subscriptionId,
    }),
  })
    .then(response => {
      return response.json();
    })
    .then(cancelSubscriptionResponse => {
      // Display to the user that the subscription has been canceled.
    });
}
On the backend, define the endpoint for your frontend to call.

server.rb
Select a language


# Set your secret key. Remember to switch to your live secret key in production.
# See your keys here: https://dashboard.stripe.com/apikeys
Stripe.api_key = 'sk_test_51R3wApPWNlED7CRw3AtCQrC6KaIRsKG7sG1szxtNSRLcNsvAOB83iR6kqU0d1EQXrWMLBllcMNggKZAXLxK9A7Iy00HDEzJYo5'

post '/cancel-subscription' do
  content_type 'application/json'
  data = JSON.parse request.body.read

  deleted_subscription = Stripe::Subscription.cancel(data['subscriptionId'])

  deleted_subscription.to_json
end
Your application receives a customer.subscription.deleted event.

After the subscription is canceled, update your database to remove the Stripe subscription ID you previously stored, and limit access to your service.

When a subscription is canceled, it can’t be reactivated. Instead, collect updated billing information from your customer, update their default payment method, and create a new subscription with their existing customer record.

Test your integration
Test payment methods
Use the following table to test different payment methods and scenarios.

Payment method	Scenario	How to test
BECS Direct Debit	Your customer successfully pays with BECS Direct Debit.	Fill out the form using the account number 900123456 and BSB 000-000. The confirmed PaymentIntent initially transitions to processing, then transitions to the succeeded status three minutes later.
BECS Direct Debit	Your customer’s payment fails with an account_closed error code.	Fill out the form using the account number 111111113 and BSB 000-000.
Credit card	The card payment succeeds and does not require authentication.	Fill out the credit card form using the credit card number 4242 4242 4242 4242 with any expiration, CVC, and postal code.
Credit card	The card payment requires authentication.	Fill out the credit card form using the credit card number 4000 0025 0000 3155 with any expiration, CVC, and postal code.
Credit card	The card is declined with a decline code like insufficient_funds.	Fill out the credit card form using the credit card number 4000 0000 0000 9995 with any expiration, CVC, and postal code.
SEPA Direct Debit	Your customer successfully pays with SEPA Direct Debit.	Fill out the form using the account number AT321904300235473204. The confirmed PaymentIntent initially transitions to processing, then transitions to the succeeded status three minutes later.
SEPA Direct Debit	Your customer’s payment intent status transition from processing to requires_payment_method.	Fill out the form using the account number AT861904300235473202.
Monitor events
Set up webhooks to listen to subscription change events, such as upgrades and cancellations. Learn more about subscription webhooks. You can view events in the Dashboard or with the Stripe CLI.

For more details, see testing your Billing integration.

Optional
Let customers change their plans
Client and Server
To let your customers change their subscription, collect the price ID of the option they want to change to. Then send the new price ID from the frontend to a backend endpoint. This example also passes the subscription ID, but you can retrieve it from your database for your logged in user.

script.js


function updateSubscription(priceId, subscriptionId) {
  return fetch('/update-subscription', {
    method: 'post',
    headers: {
      'Content-type': 'application/json',
    },
    body: JSON.stringify({
      subscriptionId: subscriptionId,
      newPriceId: priceId,
    }),
  })
    .then(response => {
      return response.json();
    })
    .then(response => {
      return response;
    });
}
On the backend, define the endpoint for your frontend to call, passing the subscription ID and the new price ID. The subscription is now Premium, at 15 USD per month, instead of Basic at 5 USD per month.

server.rb
Select a language


# Set your secret key. Remember to switch to your live secret key in production.
# See your keys here: https://dashboard.stripe.com/apikeys
Stripe.api_key = 'sk_test_51R3wApPWNlED7CRw3AtCQrC6KaIRsKG7sG1szxtNSRLcNsvAOB83iR6kqU0d1EQXrWMLBllcMNggKZAXLxK9A7Iy00HDEzJYo5'

post '/update-subscription' do
  content_type 'application/json'
  data = JSON.parse request.body.read

  subscription = Stripe::Subscription.retrieve(data['subscriptionId'])

  updated_subscription =
    Stripe::Subscription.update(
      data['subscriptionId'],
      cancel_at_period_end: false,
      items: [
        { id: subscription.items.data[0].id, price: 'price_H1NlVtpo6ubk0m' }
      ]
    )

  updated_subscription.to_json
end
Your application receives a customer.subscription.updated event.

Optional
Preview a price change
Client and Server
When your customer changes their subscription, there’s often an adjustment to the amount they owe, known as a proration. You can use the upcoming invoice endpoint to display the adjusted amount to your customers.

On the frontend, pass the upcoming invoice details to a backend endpoint.

script.js


function retrieveUpcomingInvoice(
  customerId,
  subscriptionId,
  newPriceId,
  trialEndDate
) {
  return fetch('/retrieve-upcoming-invoice', {
    method: 'post',
    headers: {
      'Content-type': 'application/json',
    },
    body: JSON.stringify({
      customerId: customerId,
      subscriptionId: subscriptionId,
      newPriceId: newPriceId,
    }),
  })
    .then(response => {
      return response.json();
    })
    .then((invoice) => {
      return invoice;
    });
}
On the backend, define the endpoint for your frontend to call.

server.rb
Select a language


# Set your secret key. Remember to switch to your live secret key in production.
# See your keys here: https://dashboard.stripe.com/apikeys
Stripe.api_key = 'sk_test_51R3wApPWNlED7CRw3AtCQrC6KaIRsKG7sG1szxtNSRLcNsvAOB83iR6kqU0d1EQXrWMLBllcMNggKZAXLxK9A7Iy00HDEzJYo5'

post '/retrieve-upcoming-invoice' do
  content_type 'application/json'
  data = JSON.parse request.body.read

  subscription = Stripe::Subscription.retrieve(data['subscriptionId'])

  invoice =
    Stripe::Invoice.upcoming(
      customer: data['customerId'],
      subscription: data['subscriptionId'],
      subscription_items: [
        { id: subscription.items.data[0].id, deleted: true },
        { price: ENV[data['newPriceId']], deleted: false }
      ]
    )

  invoice.to_json
end
Optional
Display the customer payment method
Client and Server
Displaying the brand and last four digits of your customer’s card can help them know which card is being charged, or if they need to update their payment method.

On the frontend, send the payment method ID to a backend endpoint that retrieves the payment method details.

script.js


function retrieveCustomerPaymentMethod(paymentMethodId) {
  return fetch('/retrieve-customer-payment-method', {
    method: 'post',
    headers: {
      'Content-type': 'application/json',
    },
    body: JSON.stringify({
      paymentMethodId: paymentMethodId,
    }),
  })
    .then((response) => {
      return response.json();
    })
    .then((response) => {
      return response;
    });
}
On the backend, define the endpoint for your frontend to call.

server.rb
Select a language


# Set your secret key. Remember to switch to your live secret key in production.
# See your keys here: https://dashboard.stripe.com/apikeys
Stripe.api_key = 'sk_test_51R3wApPWNlED7CRw3AtCQrC6KaIRsKG7sG1szxtNSRLcNsvAOB83iR6kqU0d1EQXrWMLBllcMNggKZAXLxK9A7Iy00HDEzJYo5'

post '/retrieve-customer-payment-method' do
  content_type 'application/json'
  data = JSON.parse request.body.read

  payment_method = Stripe::PaymentMethod.retrieve(data['paymentMethodId'])

  payment_method.to_json
end
Example response:



{
  "id": "pm_1GcbHY2eZvKYlo2CoqlVxo42",
  "object": "payment_method",
  "billing_details": {
    "address": {
      "city": null,
      "country": null,
      "line1": null,
      "line2": null,
      "postal_code": null,
See all 41 lines
Note
We recommend that you save the paymentMethod.id and last4 in your database, for example, paymentMethod.id as stripeCustomerPaymentMethodId in your users collection or table. You can optionally store exp_month, exp_year, fingerprint, billing_details as needed. This is to limit the number of calls you make to Stripe, for performance efficiency and to avoid possible rate limiting.

Disclose Stripe to your customers
Stripe collects information on customer interactions with Elements to provide services to you, prevent fraud, and improve its services. This includes using cookies and IP addresses to identify which Elements a customer saw during a single checkout session. You’re responsible for disclosing and obtaining all rights and consents necessary for Stripe to use data in these ways. For more information, visit our privacy center.


heres addiotnal docuemntion (i chose react and python) sicne tahst what i do

rontend:


HTML

React
Backend:


Ruby

Node

PHP

Python

Go

.NET

Java
Prebuilt subscription page with Stripe Checkout
View the text-based guide
Incorporate your own test mode data into our sample app to run a full, working subscription integration using Stripe Billing and Stripe Checkout.

The sample app demonstrates redirecting your customers from your site to a prebuilt payment page hosted on Stripe. The Stripe Billing APIs create and manage subscriptions, invoices, and recurring payments, while Checkout provides the prebuilt, secure, Stripe-hosted UI for collecting payment details.

Click each step to see the corresponding sample code. As you interact with the steps, such as adding pricing data, the builder updates the sample code.

Download and customize the sample app locally to test your integration.


Download full app
Don't code? Use Stripe’s no-code options or get help from our partners.
1
Set up products, pricing, and payment methods
Add your products and prices
Create new Products and Prices that you can use in this sample.

Name
Sunglasses, premium plan, etc.
Price
0.00

USD
Billing period

Monthly

Create test product
More options
Client
Add features to your product
Create features, such as an annual birthday gift, and associate them with your subscription to entitle new subscribers to them. Listen to the active entitlements summary events for your event destination, and use the list active entitlements API for a given customer to fulfill your customer’s entitlements.

Note
Create or select a product before adding a feature.
Client
Enable payment methods
Use your Dashboard to enable supported payment methods that you want to accept in addition to cards. Checkout dynamically displays your enabled payment methods in order of relevance, based on the customer’s location and other characteristics.

2
Build your subscription page
Add a pricing preview page
Add a page to your site that displays your product and allows your customers to subscribe to it. Clicking Checkout, redirects them to a Stripe-hosted Checkout page, which finalizes the order and prevents further modification.

Consider embedding a pricing table to dynamically display your pricing information through the Dashboard. Clicking a pricing option redirects your customer to the checkout page.

Client
Add a checkout button
The button on your order preview page redirects your customer to the Stripe-hosted Checkout page and uses your product’s lookup_key to retrieve the price_id from the server.

Client
Add a success page
Create a success page to display order confirmation messaging or order details to your customer. Associate this page with the Checkout Session success_url, which Stripe redirects to after the customer successfully completes the checkout.

Client
Add a customer portal button
Add a button to redirect to the customer portal to allow customers to manage their subscription. Clicking this button redirects your customer to the Stripe-hosted customer portal page.

Client
Redirect to the customer portal session
Make a request to the endpoint on your server to redirect to a new customer portal session. This sample uses the session_id from the Checkout session to demonstrate retrieving the customer_id. In a production environment, you typically store this value alongside the authenticated user in your database.

Client
3
Call the Stripe API
Install the Stripe Python package
Install the Stripe package and import it in your code. Alternatively, if you’re starting from scratch and need a requirements.txt file, download the project files using the link in the code editor.


pip

GitHub
Install the package via pip:

pip3 install stripe

Server
Create a Checkout Session
The Checkout Session controls what your customer sees in the Stripe-hosted payment page such as line items, the order amount and currency, and acceptable payment methods.

Server
Get the price from lookup key
Pass the lookup key you defined for your product in the Price endpoint to apply its price to the order.

Server
Define the line items
Always keep sensitive information about your product inventory, such as price and availability, on your server to prevent customer manipulation from the client. Pass in the predefined price ID retrieved above.

Server
Set the mode
Set the mode to subscription. Checkout also supports payment and setup modes for non-recurring payments.

Server
Supply success and cancel URLs
Specify publicly accessible URLs that Stripe can redirect customers after success or cancellation. You can provide the same URL for both properties. Add the session_id query parameter at the end of your URL so you can retrieve the customer later and so Stripe can generate the customer’s hosted Dashboard.

Server
Redirect from Checkout
After creating the session, redirect your customer to the URL returned in the response (either the success or cancel URL).

Server
Create a customer portal session
Initiate a secure, Stripe-hosted customer portal session that lets your customers manage their subscriptions and billing details.

Server
Redirect to customer portal
After creating the portal session, redirect your customer to the URL returned in the response.

Server
Fulfill the subscription
Create a /webhook endpoint and obtain your webhook secret key in the Webhooks tab in Workbench to listen for events related to subscription activity. After a successful payment and redirect to the success page, verify that the subscription status is active and grant your customer access to the products and features they subscribed to.

Server
4
Test your page
Run the server
Start your server. It automatically opens a browser window to http://localhost:3000/checkout

python3 -m flask run --port=4242

Server
Try it out
Click the checkout button. In the Stripe Checkout page, use any of these test cards to simulate a payment.

Payment succeeds

4242 4242 4242 4242
Payment requires authentication

4000 0025 0000 3155
Payment is declined

4000 0000 0000 9995
Client
Add customization features
If you successfully subscribed to your product in your test, you have a working, basic subscriptions checkout integration. Use the toggles below to see how to customize this sample with additional features.


Attach a trial period to a Checkout session.


Specify a billing cycle anchor when creating a Checkout session.


Calculate and collect the right amount of tax on your Stripe transactions. Learn more about Stripe Tax and how to add it to Checkout. Activate Stripe Tax in the Dashboard before integrating.

Next steps
Update subscription prices
Update subscriptions to handle customers upgrading or downgrading their subscription plan.

Apply prorations
Learn how to adjust a customer’s invoice to accurately reflect mid-cycle pricing changes.

Offer upsells
Incentivize customers with discounts for committing to longer billing intervals.

More features
Review the features to further customize your integration to offer discounts, pause payment collection, and more.

Was this page helpful?
Yes
No

App.js

server.py

Download
#! /usr/bin/env python3.6

"""
server.py
Stripe Sample.
Python 3.6 or newer required.
"""
import os
from flask import Flask, redirect, jsonify, json, request, current_app

import stripe
# This is your test secret API key.
stripe.api_key = 'sk_test_51R3wApPWNlED7CRw3AtCQrC6KaIRsKG7sG1szxtNSRLcNsvAOB83iR6kqU0d1EQXrWMLBllcMNggKZAXLxK9A7Iy00HDEzJYo5'

app = Flask(__name__,
            static_url_path='',
            static_folder='public')

YOUR_DOMAIN = 'http://localhost:4242'

@app.route('/', methods=['GET'])
def get_index():
    return current_app.send_static_file('index.html')

@app.route('/create-checkout-session', methods=['POST'])
def create_checkout_session():
    try:
        prices = stripe.Price.list(
            lookup_keys=[request.form['lookup_key']],
            expand=['data.product']
        )

        checkout_session = stripe.checkout.Session.create(
            line_items=[
                {
                    'price': prices.data[0].id,
                    'quantity': 1,
                },
            ],
            mode='subscription',
            success_url=YOUR_DOMAIN +
            '?success=true&session_id={CHECKOUT_SESSION_ID}',
            cancel_url=YOUR_DOMAIN + '?canceled=true',
        )
        return redirect(checkout_session.url, code=303)
    except Exception as e:
        print(e)
        return "Server error", 500

@app.route('/create-portal-session', methods=['POST'])
def customer_portal():
    # For demonstration purposes, we're using the Checkout session to retrieve the customer ID.
    # Typically this is stored alongside the authenticated user in your database.
    checkout_session_id = request.form.get('session_id')
    checkout_session = stripe.checkout.Session.retrieve(checkout_session_id)

    # This is the URL to which the customer will be redirected after they're
    # done managing their billing with the portal.
    return_url = YOUR_DOMAIN

    portalSession = stripe.billing_portal.Session.create(
        customer=checkout_session.customer,
        return_url=return_url,
    )
    return redirect(portalSession.url, code=303)

@app.route('/webhook', methods=['POST'])
def webhook_received():
    # Replace this endpoint secret with your endpoint's unique secret
    # If you are testing with the CLI, find the secret by running 'stripe listen'
    # If you are using an endpoint defined with the API or dashboard, look in your webhook settings
    # at https://dashboard.stripe.com/webhooks
    webhook_secret = 'whsec_12345'
    request_data = json.loads(request.data)

    if webhook_secret:
        # Retrieve the event by verifying the signature using the raw body and secret if webhook signing is configured.
        signature = request.headers.get('stripe-signature')
        try:
            event = stripe.Webhook.construct_event(
                payload=request.data, sig_header=signature, secret=webhook_secret)
            data = event['data']
        except Exception as e:
            return e
        # Get the type of webhook event sent - used to check the status of PaymentIntents.
        event_type = event['type']
    else:
        data = request_data['data']
        event_type = request_data['type']
    data_object = data['object']

    print('event ' + event_type)

    if event_type == 'checkout.session.completed':
        print('🔔 Payment succeeded!')
    elif event_type == 'customer.subscription.trial_will_end':
        print('Subscription trial will end')
    elif event_type == 'customer.subscription.created':
        print('Subscription created %s', event.id)
    elif event_type == 'customer.subscription.updated':
        print('Subscription created %s', event.id)
    elif event_type == 'customer.subscription.deleted':
        # handle subscription canceled automatically based
        # upon your subscription settings. Or if the user cancels it.
        print('Subscription canceled: %s', event.id)
    elif event_type == 'entitlements.active_entitlement_summary.updated':
        # handle active entitlement summary updated
        print('Active entitlement summary updated: %s', event.id)

    return jsonify({'status': 'success'})


and ofocurse you might know already hwo to do it but thought id porvide some  theie wbeiste documents aswell fro extra help but dont soley rely on just he documentation i gave you yah know- just do you rhtinga dn do whats best for me thank you!!!

