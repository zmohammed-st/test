import {
	Html,
	Container,
	Text,
	Head,
	Body,
	Button,
	Section,
	Heading,
	Preview,
	Tailwind,
} from '@react-email/components'

export interface ForgotPasswordEmailProps {
	onboardingUrl: string
	otp: string
	firstName?: string
}

export default function ForgotPasswordEmail({
	onboardingUrl,
	otp,
	firstName = 'Developer',
}: ForgotPasswordEmailProps) {
	return (
		<Html lang="en" dir="ltr">
			<Tailwind>
				<Head />
				<Preview>Reset your Epic Startup password</Preview>
				<Body className="bg-[#F6F8FA] py-[40px] font-sans">
					<Container className="mx-auto max-w-[600px] rounded-[8px] bg-[#FFFFFF] px-[32px] py-[40px]">
						{/* Main Content */}
						<Section>
							<Heading className="mb-[16px] text-center text-[24px] font-bold text-[#020304]">
								Reset Your Password, {firstName}
							</Heading>

							<Text className="mb-[24px] text-[16px] leading-[24px] text-[#020304]">
								We received a request to reset your Epic Startup password. If
								you didn't make this request, you can safely ignore this email.
							</Text>

							<Text className="mb-[16px] text-[16px] leading-[24px] text-[#020304]">
								Here's your verification code:{' '}
								<strong className="text-[#2563eb]">{otp}</strong>
							</Text>

							<Text className="mb-[24px] text-[16px] leading-[24px] text-[#020304]">
								Or click the button below to reset your password:
							</Text>

							<Section className="mb-[32px] text-center">
								<Button
									href={onboardingUrl}
									className="box-border rounded-[6px] bg-[#2563eb] px-[24px] py-[12px] text-[16px] font-medium text-white no-underline"
								>
									Reset Password
								</Button>
							</Section>

							<Text className="mb-[16px] text-[16px] leading-[24px] text-[#020304]">
								For security reasons, please reset your password promptly. If
								you need help, our support team is here to assist you.
							</Text>

							<Text className="text-[16px] leading-[24px] text-[#020304]">
								Stay secure!
								<br />
								The Epic Startup Team
							</Text>
						</Section>

						{/* Footer */}
						<Section className="mt-[40px] border-t border-solid border-[#E5E7EB] pt-[32px]">
							<Text className="mb-[8px] text-center text-[14px] leading-[20px] text-[#6B7280]">
								Organize your thoughts with Epic Startup
							</Text>
							<Text className="mb-[8px] text-center text-[12px] leading-[16px] text-[#6B7280]">
								If the button doesn't work, copy this link: {onboardingUrl}
							</Text>
							<Text className="m-0 text-center text-[12px] leading-[16px] text-[#6B7280]">
								Copyright © 2025 Epic Startup
							</Text>
						</Section>
					</Container>
				</Body>
			</Tailwind>
		</Html>
	)
}

ForgotPasswordEmail.PreviewProps = {
	onboardingUrl: 'https://example.com/verify/abc123',
	otp: '123456',
	firstName: 'Alex',
} as ForgotPasswordEmailProps
